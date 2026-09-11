package azure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// --- the whole guided flow against fakes -------------------------------------
//
// Nothing in this file touches Azure. The identity platform is fakeLogin
// (auth_test.go), the management plane is armState (create_test.go) plus the
// one route the guided flow needs that armState does not answer, and the data
// plane is blobStore (azure_test.go). No live sign-in has ever been run in
// this project, so these tests are the only evidence there is, and they prove
// the order of the steps and the refusals, not that Azure behaves this way.

// azureFake wires all three fakes into the two transport seams Setup takes.
type azureFake struct {
	t     *testing.T
	login *fakeLogin
	arm   *armState
	blobs *blobStore

	subs []Subscription
	// denyAdminBlobPut makes the administrator's own write probe fail while
	// the unattended uploader's succeeds. That is the ordinary case on the
	// creation path: Contributor creates a storage account and grants no
	// access at all to a blob inside it.
	denyAdminBlobPut bool
}

func newAzureFake(t *testing.T) *azureFake {
	t.Helper()
	return &azureFake{
		t: t,
		login: &fakeLogin{t: t,
			device: httpResponse(http.StatusOK, `{"device_code":"`+deviceSecret+`",
				"user_code":"KTQ7X9YR","verification_uri":"https://microsoft.com/devicelogin",
				"expires_in":900,"interval":5,
				"message":"To sign in, open https://microsoft.com/devicelogin and enter the code KTQ7X9YR."}`, nil),
			// One for the completed device-code flow, the rest for the storage
			// scope the same sign-in is redeemed for.
			replies: []*http.Response{
				tokenReply(testToken, refreshToken, 3600),
				tokenReply(testToken, refreshToken, 3600),
				tokenReply(testToken, refreshToken, 3600),
			},
		},
		arm:   newARM(t),
		blobs: newBlobStore(t),
		subs:  []Subscription{{ID: testSub, Name: "Production", State: "Enabled"}},
	}
}

// do is the administrator's transport.
func (f *azureFake) do(req *http.Request) (*http.Response, error) {
	if f.denyAdminBlobPut && req.Method == http.MethodPut &&
		strings.Contains(req.URL.Host, ".blob.core.windows.net") {
		f.blobs.calls = append(f.blobs.calls, "DENIED PUT "+req.URL.Path)
		return httpResponse(http.StatusForbidden,
			`<?xml version="1.0"?><Error><Code>AuthorizationPermissionMismatch</Code>`+
				`<Message>This request is not authorized to perform this operation using this permission.</Message></Error>`, nil), nil
	}
	return f.serve(req)
}

// serve answers management and blob requests from whichever fake owns them.
func (f *azureFake) serve(req *http.Request) (*http.Response, error) {
	if strings.Contains(req.URL.Host, "management.azure.com") {
		// armState answers a subscription by ID but not the list, which only
		// the guided flow asks for.
		if req.URL.Path == "/subscriptions" {
			f.arm.calls = append(f.arm.calls, req.Method+" "+req.URL.Path)
			return armJSON(http.StatusOK, map[string]any{"value": f.subs}), nil
		}
		return f.arm.serve(req)
	}
	return f.blobs.serve(req)
}

// uploaderClient is a client signed in as the unattended service principal.
// It is a different identity from the administrator's and reaches the blob
// service directly, which is what makes "the uploader proved it" a different
// statement from "the administrator proved it".
func (f *azureFake) uploaderClient() *Client {
	return &Client{Token: testTokens, Sleep: func(time.Duration) {}, Do: f.serve}
}

func (f *azureFake) puts() int { return f.arm.countCalls(http.MethodPut, "") }

// fakeOperator is the administrator at the other end of the seam. It answers
// from a script and records every question and every line, in order, so a test
// can assert that the plan was shown before the approval was asked for.
type fakeOperator struct {
	t *testing.T

	confirms []bool // answers to Confirm, consumed in order
	choices  []int  // answers to Choose, consumed in order
	answer   string // what Ask returns

	events  []string
	chosen  []string // the prompt of every Choose put
	offered [][]string

	journalled         []Creation
	journalCalls       int
	putsWhenJournalled int
}

func (op *fakeOperator) say(format string, args ...any) {
	op.events = append(op.events, "say: "+fmt.Sprintf(format, args...))
}

func (op *fakeOperator) confirm(question string) (bool, error) {
	op.events = append(op.events, "confirm: "+question)
	if len(op.confirms) == 0 {
		op.t.Fatalf("the flow asked a question the test did not script: %q", question)
	}
	a := op.confirms[0]
	op.confirms = op.confirms[1:]
	return a, nil
}

func (op *fakeOperator) choose(prompt string, options []string) (int, error) {
	op.events = append(op.events, "choose: "+prompt+" "+strings.Join(options, " | "))
	op.chosen = append(op.chosen, prompt)
	op.offered = append(op.offered, options)
	if len(op.choices) == 0 {
		op.t.Fatalf("the flow put a choice the test did not script: %q %v", prompt, options)
	}
	a := op.choices[0]
	op.choices = op.choices[1:]
	return a, nil
}

func (op *fakeOperator) ask(prompt, def string) (string, error) {
	op.events = append(op.events, "ask: "+prompt)
	if op.answer == "" {
		op.t.Fatalf("the flow asked for free text the test did not script: %q", prompt)
	}
	return op.answer, nil
}

func (op *fakeOperator) transcript() string { return strings.Join(op.events, "\n") }

// at returns the position of the first event containing substr, or -1.
func (op *fakeOperator) at(substr string) int {
	for i, e := range op.events {
		if strings.Contains(e, substr) {
			return i
		}
	}
	return -1
}

func setupOptions(f *azureFake, op *fakeOperator) SetupOptions {
	return SetupOptions{
		App:          newApp(f.login),
		DeploymentID: testDeployment,
		Hostname:     "guac.example.com",
		Say:          op.say,
		Ask:          op.ask,
		Confirm:      op.confirm,
		Choose:       op.choose,
		Journal: func(cs []Creation) error {
			op.journalled = append(op.journalled, cs...)
			op.journalCalls++
			op.putsWhenJournalled = f.puts()
			return nil
		},
		Do:       f.do,
		Sleep:    func(time.Duration) {},
		RoleWait: RoleWait{Within: time.Second, Interval: time.Millisecond, Sleep: func(time.Duration) {}},
	}
}

// existingDestination puts the reuse path's storage in place.
func (f *azureFake) existingDestination() {
	f.arm.existingAccount("acctbackups", "rg-backups", nil)
	f.arm.existingContainer("acctbackups", "guacdeploy", nil)
}

// --- declining ---------------------------------------------------------------

// TestDecliningAzureConfiguresNothingAndIsNotAFailure. An Azure destination is
// optional, so "no" is an answer rather than an error — and nothing is signed
// in to, which is the part that matters: a declined offer must not put a
// device code on the screen or reach Azure at all.
func TestDecliningAzureConfiguresNothingAndIsNotAFailure(t *testing.T) {
	f := newAzureFake(t)
	op := &fakeOperator{t: t, confirms: []bool{false}}

	res, err := Setup(context.Background(), setupOptions(f, op))
	if err != nil {
		t.Fatalf("declining an optional destination was reported as a failure: %v", err)
	}
	if res.Configured {
		t.Fatalf("declining Azure configured a destination: %+v", res.Destination)
	}
	if !strings.Contains(res.Reason, "no destination configured") {
		t.Fatalf("the result does not say why there is no destination: %q", res.Reason)
	}
	if len(f.login.forms) != 0 {
		t.Fatalf("declining Azure still signed in: %d requests to the identity platform", len(f.login.forms))
	}
	if len(f.arm.calls) != 0 {
		t.Fatalf("declining Azure still called Azure: %v", f.arm.calls)
	}
	if !strings.Contains(op.transcript(), "No Azure destination configured") {
		t.Fatalf("the administrator was not told what was decided:\n%s", op.transcript())
	}
}

// TestAPreselectedDestinationIsNotOfferedAgain: an operator who named the
// storage on the command line has already said yes, and a question with one
// possible answer in an unattended run is a hang waiting to happen.
func TestAPreselectedDestinationIsNotOfferedAgain(t *testing.T) {
	f := newAzureFake(t)
	f.existingDestination()
	op := &fakeOperator{t: t} // any question at all fails the test

	o := setupOptions(f, op)
	o.Account, o.Container = "acctbackups", "guacdeploy"
	if _, err := Setup(context.Background(), o); err != nil {
		t.Fatal(err)
	}
}

// --- choosing the subscription ----------------------------------------------

// TestSubscriptionSelection covers the three shapes of the subscription step:
// exactly one (say which, ask nothing), none (explain what that means), and
// several (ask). A pre-set subscription that the account cannot see is named
// alongside the ones it can.
func TestSubscriptionSelection(t *testing.T) {
	second := Subscription{ID: "99999999-8888-7777-6666-555555555555", Name: "Sandbox", State: "Enabled"}
	cases := []struct {
		name     string
		subs     []Subscription
		preset   string
		choices  []int
		want     string
		wantErr  []string
		wantSaid string
		asks     bool
	}{
		{
			name: "the only subscription is used and named", subs: []Subscription{{ID: testSub, Name: "Production"}},
			want: testSub, wantSaid: "Using the only subscription this account can see: Production",
		},
		{
			name: "no subscription is explained", subs: nil,
			wantErr: []string{"can see no Azure subscriptions", "Sign in with an account that can see the subscription"},
		},
		{
			name:    "several subscriptions are put to the administrator",
			subs:    []Subscription{{ID: testSub, Name: "Production"}, second},
			choices: []int{1}, want: second.ID, asks: true,
		},
		{
			name:   "a pre-set subscription is used without asking",
			subs:   []Subscription{{ID: testSub, Name: "Production"}, second},
			preset: second.ID, want: second.ID,
		},
		{
			name:    "a pre-set subscription the account cannot see names the ones it can",
			subs:    []Subscription{{ID: testSub, Name: "Production"}},
			preset:  "00000000-0000-0000-0000-000000000000",
			wantErr: []string{"is not one of the 1 this account can see", "Production " + testSub},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newAzureFake(t)
			f.subs = tc.subs
			op := &fakeOperator{t: t, choices: tc.choices}
			o := setupOptions(f, op)
			o.SubscriptionID = tc.preset
			if err := o.defaults(); err != nil {
				t.Fatal(err)
			}
			c := &Client{Token: testTokens, Do: f.do}

			got, err := o.subscription(context.Background(), c)
			if len(tc.wantErr) > 0 {
				if err == nil {
					t.Fatalf("selection succeeded with %+v", got)
				}
				for _, want := range tc.wantErr {
					if !strings.Contains(err.Error(), want) {
						t.Fatalf("the error does not say %q:\n%v", want, err)
					}
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.ID != tc.want {
				t.Fatalf("selected %s, want %s", got.ID, tc.want)
			}
			if asked := len(op.chosen) > 0; asked != tc.asks {
				t.Fatalf("the administrator was asked = %v, want %v (%v)", asked, tc.asks, op.chosen)
			}
			if tc.wantSaid != "" && !strings.Contains(op.transcript(), tc.wantSaid) {
				t.Fatalf("the administrator was not told %q:\n%s", tc.wantSaid, op.transcript())
			}
		})
	}
}

// --- reusing existing storage ------------------------------------------------

// TestReuseSelectsExistingStorageAndCreatesNothing is the whole reuse path:
// the account and the container are offered, one of each is chosen, the
// permissions are proved by a real write, and no management-plane write is
// sent at all.
func TestReuseSelectsExistingStorageAndCreatesNothing(t *testing.T) {
	f := newAzureFake(t)
	f.existingDestination()
	f.arm.existingContainer("acctbackups", "other", nil)
	op := &fakeOperator{t: t, confirms: []bool{true}, choices: []int{0, 0}}

	res, err := Setup(context.Background(), setupOptions(f, op))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Configured {
		t.Fatalf("a proved destination was not recorded: %+v", res)
	}
	if res.Destination.Account != "acctbackups" || res.Destination.AccountID != testAccountID {
		t.Fatalf("destination = %+v", res.Destination)
	}
	if f.puts() != 0 {
		t.Fatalf("the reuse path wrote to the management plane: %v", f.arm.calls)
	}
	if len(res.Created) != 0 {
		t.Fatalf("the reuse path recorded a creation: %+v", res.Created)
	}
	if len(res.Reused) != 2 {
		t.Fatalf("the reuse path recorded %d reused resources, want the account and the container: %+v", len(res.Reused), res.Reused)
	}
	for _, r := range res.Reused {
		if !strings.Contains(r.Ownership, "pre-existing") {
			t.Fatalf("storage this deployment did not create is recorded as %q", r.Ownership)
		}
		if r.ProviderID == "" {
			t.Fatalf("%s has no resource ID for the parent to record: %+v", r.Type, r)
		}
	}
	if res.BlobDataProvenBy != "the signed-in administrator, by a real write" {
		t.Fatalf("blob data access was recorded as proved by %q", res.BlobDataProvenBy)
	}
	// The container menu offers what exists and nothing else: creating a
	// container inside somebody else's storage account is not a path here.
	if len(op.offered) != 2 {
		t.Fatalf("menus put: %v", op.offered)
	}
	for _, label := range op.offered[1] {
		if strings.Contains(strings.ToLower(label), "create") {
			t.Fatalf("the container menu offered creation inside a pre-existing account: %v", op.offered[1])
		}
	}
}

// TestTheDeploymentsOwnStorageIsUsedAgainRatherThanOfferedAsAChoice. A second
// account or container carrying the same marker is a case only a person can
// resolve, so the one that already carries it is used without asking.
func TestTheDeploymentsOwnStorageIsUsedAgainRatherThanOfferedAsAChoice(t *testing.T) {
	f := newAzureFake(t)
	marker := map[string]string{ownerMetadata: testDeployment}
	f.arm.existingAccount("somebodyelse", "rg-other", nil)
	f.arm.existingAccount("acctbackups", "rg-backups", marker)
	f.arm.existingContainer("acctbackups", "unrelated", nil)
	f.arm.existingContainer("acctbackups", "guacdeploy", marker)
	op := &fakeOperator{t: t, confirms: []bool{true}} // no menu may be put

	res, err := Setup(context.Background(), setupOptions(f, op))
	if err != nil {
		t.Fatal(err)
	}
	if res.Destination.Account != "acctbackups" || res.Destination.Container != "guacdeploy" {
		t.Fatalf("destination = %+v", res.Destination)
	}
	if len(op.chosen) != 0 {
		t.Fatalf("storage this deployment already owns was put to the administrator as a choice: %v", op.chosen)
	}
	for _, r := range res.Reused {
		if !strings.Contains(r.Ownership, "earlier run of this deployment") {
			t.Fatalf("%s ownership recorded as %q", r.Type, r.Ownership)
		}
	}
}

// TestAnAccountWithNoContainerIsRefusedWithTheReasonAndTheAlternative. This
// tool does not create a container inside a storage account it did not create,
// because PlanCreate refuses a storage account that matches by name without
// this deployment's marker. The message has to say so and name the way out.
func TestAnAccountWithNoContainerIsRefusedWithTheReasonAndTheAlternative(t *testing.T) {
	f := newAzureFake(t)
	f.arm.existingAccount("acctbackups", "rg-backups", nil)
	op := &fakeOperator{t: t, confirms: []bool{true}, choices: []int{0}}

	_, err := Setup(context.Background(), setupOptions(f, op))
	if err == nil {
		t.Fatal("an account with no container was accepted")
	}
	for _, want := range []string{"no containers", "did not create", "ask for creation"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the error does not say %q:\n%v", want, err)
		}
	}
	if f.puts() != 0 {
		t.Fatalf("a container was created inside a pre-existing account: %v", f.arm.calls)
	}
}

// --- creating storage --------------------------------------------------------

func createOptions(f *azureFake, op *fakeOperator) SetupOptions {
	o := setupOptions(f, op)
	o.Create, o.Location = true, "australiaeast"
	return o
}

// TestCreationStopsWhenReusingAPreExistingResourceGroupIsDeclined is the
// approval gate. The plan has to be on the screen before the question is put,
// and a "no" has to leave Azure untouched.
func TestCreationStopsWhenReusingAPreExistingResourceGroupIsDeclined(t *testing.T) {
	f := newAzureFake(t)
	group := ResourceGroupName("guac.example.com", testDeployment)
	f.arm.existingGroup(group, map[string]string{"owner": "somebody-else"})
	op := &fakeOperator{t: t, confirms: []bool{false}}

	res, err := Setup(context.Background(), createOptions(f, op))
	if !errors.Is(err, ErrApprovalRequired) {
		t.Fatalf("declining the reuse of a pre-existing resource group returned %v", err)
	}
	if res.Configured {
		t.Fatal("a declined creation configured a destination")
	}
	if f.puts() != 0 {
		t.Fatalf("something was created without approval: %v", f.arm.calls)
	}
	summary, question := op.at("Subscription:   "+testSub), op.at("confirm: Reuse the existing resource group")
	if summary < 0 || question < 0 {
		t.Fatalf("the plan was not shown, or the approval was not asked for:\n%s", op.transcript())
	}
	if summary > question {
		t.Fatalf("the approval was asked for before the plan was shown:\n%s", op.transcript())
	}
	if !strings.Contains(op.transcript(), "pre-existing, not created by this deployment") {
		t.Fatalf("the plan did not say the group is not ours:\n%s", op.transcript())
	}
}

// TestCreationWithoutApprovalIsRefusedWhenNobodyCanBeAsked. An unattended run
// that reaches the approval must stop, not assume it. Specification A8.
func TestCreationWithoutApprovalIsRefusedWhenNobodyCanBeAsked(t *testing.T) {
	f := newAzureFake(t)
	group := ResourceGroupName("guac.example.com", testDeployment)
	f.arm.existingGroup(group, map[string]string{"owner": "somebody-else"})
	op := &fakeOperator{t: t}

	o := createOptions(f, op)
	o.Confirm = nil // as an unattended parent leaves it
	if _, err := Setup(context.Background(), o); err == nil {
		t.Fatal("an unattended run approved the reuse of somebody else's resource group")
	} else if !strings.Contains(err.Error(), "no interactive seam") {
		t.Fatalf("the refusal does not say why it could not be answered: %v", err)
	}
	if f.puts() != 0 {
		t.Fatalf("something was created without approval: %v", f.arm.calls)
	}
}

// TestCreationJournalsTheIntentBeforeItSendsAnything is the recoverability
// rule: the intent reaches the parent's journal before the first write leaves,
// so a lost response can be reconciled by marker on the next run.
func TestCreationJournalsTheIntentBeforeItSendsAnything(t *testing.T) {
	f := newAzureFake(t)
	op := &fakeOperator{t: t}

	if _, err := Setup(context.Background(), createOptions(f, op)); err != nil {
		t.Fatal(err)
	}
	if op.journalCalls != 1 {
		t.Fatalf("the creation intent was journalled %d times", op.journalCalls)
	}
	if op.putsWhenJournalled != 0 {
		t.Fatalf("%d resources were written before the intent was journalled", op.putsWhenJournalled)
	}
	want := []Creation{
		{Type: "resource-group", Name: ResourceGroupName("guac.example.com", testDeployment)},
		{Type: "storage-account", Name: AccountName("guac.example.com", testDeployment)},
		{Type: "blob-container", Name: DefaultContainer},
	}
	if fmt.Sprint(op.journalled) != fmt.Sprint(want) {
		t.Fatalf("journalled %v, want %v", op.journalled, want)
	}
}

// TestCreationWithoutAJournalIsRefused: creating without a journal seam is a
// wiring mistake that only shows up after a lost response, which is the worst
// possible time to find it.
func TestCreationWithoutAJournalIsRefused(t *testing.T) {
	f := newAzureFake(t)
	op := &fakeOperator{t: t}
	o := createOptions(f, op)
	o.Journal = nil

	if _, err := Setup(context.Background(), o); err == nil {
		t.Fatal("storage was created with no journalled intent")
	} else if !strings.Contains(err.Error(), "SetupOptions.Journal") {
		t.Fatalf("the refusal does not name the missing seam: %v", err)
	}
	if f.puts() != 0 {
		t.Fatalf("something was created with no journalled intent: %v", f.arm.calls)
	}
}

// TestCreationRecordsWhatItMadeAndProvesTheUploadersAccess is the creation
// path end to end, in the shape it really has: the administrator can create a
// storage account and still cannot write a blob inside it, so the proof of
// blob data access comes from the unattended uploader after its role lands.
func TestCreationRecordsWhatItMadeAndProvesTheUploadersAccess(t *testing.T) {
	f := newAzureFake(t)
	f.denyAdminBlobPut = true
	op := &fakeOperator{t: t}
	o := createOptions(f, op)
	o.UploaderObjectID = "0bf2aa58-1111-2222-3333-444444444444"
	o.Uploader = f.uploaderClient()

	res, err := Setup(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Configured || res.Location != "australiaeast" {
		t.Fatalf("result = %+v", res)
	}
	if res.BlobDataProvenBy != "the unattended uploader, by a real write after the role took effect" {
		t.Fatalf("blob data access was recorded as proved by %q, though the administrator could not write one", res.BlobDataProvenBy)
	}
	if res.Preflight.BlobData.OK {
		t.Fatal("the administrator's write probe was reported as passing while every blob PUT of theirs was refused")
	}

	got := map[string]Created{}
	for _, cr := range res.Created {
		got[cr.Type] = cr
	}
	for _, want := range []struct{ kind, ownership string }{
		{"resource-group", "tag " + ownerMetadata + "=" + testDeployment},
		{"storage-account", "tag " + ownerMetadata + "=" + testDeployment},
		{"blob-container", "container metadata " + ownerMetadata + "=" + testDeployment},
		{"role-assignment", roleOwnership},
	} {
		cr, ok := got[want.kind]
		if !ok {
			t.Fatalf("%s was created and not recorded: %+v", want.kind, res.Created)
		}
		if cr.Ownership != want.ownership {
			t.Fatalf("%s ownership recorded as %q, want %q", want.kind, cr.Ownership, want.ownership)
		}
		if !strings.HasPrefix(cr.ProviderID, "/subscriptions/"+testSub) {
			t.Fatalf("%s has no usable resource ID: %q", want.kind, cr.ProviderID)
		}
	}
	if len(res.Reused) != 0 {
		t.Fatalf("a resource this run created was recorded as reused: %+v", res.Reused)
	}
	if res.RoleAssignment == nil || !res.RoleAssignment.Created {
		t.Fatalf("role assignment = %+v", res.RoleAssignment)
	}
	if res.RoleEffective == nil || !res.RoleEffective.OK {
		t.Fatalf("the granted role was not proved: %+v", res.RoleEffective)
	}
	if !strings.Contains(op.transcript(), "eventually consistent") ||
		!strings.Contains(op.transcript(), "several minutes") {
		t.Fatalf("the administrator was not told role propagation takes time:\n%s", op.transcript())
	}
}

// TestCreationReusesTheStorageThisDeploymentAlreadyOwns. A resumed or repeated
// setup finds its own resource group, account and container by marker and
// creates nothing a second time.
func TestCreationReusesTheStorageThisDeploymentAlreadyOwns(t *testing.T) {
	f := newAzureFake(t)
	marker := map[string]string{ownerMetadata: testDeployment}
	group := ResourceGroupName("guac.example.com", testDeployment)
	account := AccountName("guac.example.com", testDeployment)
	f.arm.existingGroup(group, marker)
	f.arm.existingAccount(account, group, marker)
	f.arm.existingContainer(account, DefaultContainer, marker)
	op := &fakeOperator{t: t}

	res, err := Setup(context.Background(), createOptions(f, op))
	if err != nil {
		t.Fatal(err)
	}
	if f.puts() != 0 {
		t.Fatalf("storage this deployment already owns was created again: %v", f.arm.calls)
	}
	if len(res.Created) != 0 {
		t.Fatalf("nothing was created, but the result claims %+v", res.Created)
	}
	if len(res.Reused) != 3 {
		t.Fatalf("reused = %+v, want the resource group, the account and the container", res.Reused)
	}
	for _, r := range res.Reused {
		if !strings.Contains(r.Ownership, "earlier run of this deployment") {
			t.Fatalf("%s ownership recorded as %q", r.Type, r.Ownership)
		}
	}
	if op.journalCalls != 0 {
		t.Fatalf("a plan that creates nothing journalled an intent %d times", op.journalCalls)
	}
	if !res.Configured || res.Destination.Container != DefaultContainer {
		t.Fatalf("result = %+v", res)
	}
}

// TestAnAskedForRegionReachesTheCreation: there is no default region, so an
// administrator who did not supply one is asked, and the answer is what gets
// created.
func TestAnAskedForRegionReachesTheCreation(t *testing.T) {
	f := newAzureFake(t)
	op := &fakeOperator{t: t, answer: "australiasoutheast"}
	o := createOptions(f, op)
	o.Location = ""

	res, err := Setup(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if res.Location != "australiasoutheast" {
		t.Fatalf("created in %q", res.Location)
	}
	group := ResourceGroupName("guac.example.com", testDeployment)
	body := f.arm.bodyOf("/subscriptions/" + testSub + "/resourcegroups/" + group)
	if body["location"] != "australiasoutheast" {
		t.Fatalf("the resource group was created in %v", body["location"])
	}
}

// --- permissions -------------------------------------------------------------

// TestADestinationWithoutProvenBlobAccessIsNotRecorded. A listing is not
// evidence and a role assignment is not evidence: only a write that happened
// is. Without one, no destination is recorded and the error names the role.
func TestADestinationWithoutProvenBlobAccessIsNotRecorded(t *testing.T) {
	f := newAzureFake(t)
	f.existingDestination()
	f.blobs.denyPut = true
	op := &fakeOperator{t: t}
	o := setupOptions(f, op)
	o.Account, o.Container = "acctbackups", "guacdeploy"

	res, err := Setup(context.Background(), o)
	if err == nil {
		t.Fatal("a destination nobody could write a blob to was accepted")
	}
	if res.Configured {
		t.Fatal("a destination with unproved blob access was recorded")
	}
	if res.BlobDataProvenBy != "" {
		t.Fatalf("blob data access was claimed as proved by %q", res.BlobDataProvenBy)
	}
	for _, want := range []string{"has not been proved", UploaderRole, "no unattended uploader was named"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the error does not say %q:\n%v", want, err)
		}
	}
}

// TestAManagementFailureStopsBeforeAnythingElse: an identity that cannot see
// the storage account is told that, with the role that fixes it, rather than
// being sent to look at blob permissions.
func TestAManagementFailureStopsBeforeAnythingElse(t *testing.T) {
	f := newAzureFake(t)
	f.existingDestination()
	op := &fakeOperator{t: t}
	o := setupOptions(f, op)
	o.Account, o.Container = "acctbackups", "guacdeploy"
	// The account is visible in the subscription-wide listing that selects it
	// and cannot be read on its own, which is what a Reader role removed
	// between the two calls looks like.
	inner := f.do
	o.Do = func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodGet && strings.HasSuffix(req.URL.Path, "/storageAccounts/acctbackups") {
			return armErr(http.StatusNotFound, "ResourceNotFound", "The storage account was not found."), nil
		}
		return inner(req)
	}

	res, err := Setup(context.Background(), o)
	if err == nil {
		t.Fatal("a destination whose account cannot be read was accepted")
	}
	if res.Configured {
		t.Fatal("a destination that failed the management check was recorded")
	}
	if !strings.Contains(err.Error(), CheckManagement) {
		t.Fatalf("the error does not name the check that failed:\n%v", err)
	}
}

// TestAGrantedRoleThatNeverTakesEffectBlocksTheDestination. The assignment PUT
// succeeding is not proof. When the write probe keeps failing, the destination
// is refused and the message says role propagation is the likely reason.
func TestAGrantedRoleThatNeverTakesEffectBlocksTheDestination(t *testing.T) {
	f := newAzureFake(t)
	f.existingDestination()
	f.blobs.denyPut = true
	op := &fakeOperator{t: t}
	o := setupOptions(f, op)
	o.Account, o.Container = "acctbackups", "guacdeploy"
	o.UploaderObjectID = "0bf2aa58-1111-2222-3333-444444444444"
	o.Uploader = f.uploaderClient()

	res, err := Setup(context.Background(), o)
	if err == nil {
		t.Fatal("a role that never took effect was treated as proof")
	}
	if res.Configured {
		t.Fatal("a destination whose uploader cannot write was recorded")
	}
	if res.RoleAssignment == nil {
		t.Fatal("the role assignment was not recorded, so the parent cannot record what it made")
	}
	if res.RoleEffective == nil || res.RoleEffective.OK {
		t.Fatalf("role proof = %+v", res.RoleEffective)
	}
	if !strings.Contains(err.Error(), "had not taken effect") {
		t.Fatalf("the error does not explain what was waited for:\n%v", err)
	}
}

// TestNoUploaderIsReportedRatherThanQuietlyAccepted: a destination the
// administrator can write to still has no unattended access, and a scheduled
// upload that fails at 2am must not be the first time anybody hears about it.
func TestNoUploaderIsReportedRatherThanQuietlyAccepted(t *testing.T) {
	f := newAzureFake(t)
	f.existingDestination()
	op := &fakeOperator{t: t}
	o := setupOptions(f, op)
	o.Account, o.Container = "acctbackups", "guacdeploy"

	res, err := Setup(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Configured || res.RoleAssignment != nil {
		t.Fatalf("result = %+v", res)
	}
	if !strings.Contains(op.transcript(), "Scheduled uploads fail until") {
		t.Fatalf("the administrator was not warned that nothing can upload unattended:\n%s", op.transcript())
	}
}

// --- secrets -----------------------------------------------------------------

// TestNoSignInValueReachesTheOperatorOrTheResult. The administrator has to see
// the user code and the verification URL, and nothing else: not the device
// code, not an access token, not a refresh token. The Result is persisted by
// the parent, so it is checked serialised as well as rendered.
func TestNoSignInValueReachesTheOperatorOrTheResult(t *testing.T) {
	f := newAzureFake(t)
	f.existingDestination()
	op := &fakeOperator{t: t}
	o := setupOptions(f, op)
	o.Account, o.Container = "acctbackups", "guacdeploy"
	o.UploaderObjectID = "0bf2aa58-1111-2222-3333-444444444444"
	o.Uploader = f.uploaderClient()

	res, err := Setup(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	haystacks := map[string]string{
		"the transcript the administrator saw": op.transcript(),
		"the rendered result":                  fmt.Sprintf("%+v", res),
		"the serialised result":                string(encoded),
	}
	for where, text := range haystacks {
		for _, secret := range []string{deviceSecret, testToken, refreshToken, accessToken, clientSecret} {
			if strings.Contains(text, secret) {
				t.Fatalf("%s contains a credential", where)
			}
		}
	}
	if !strings.Contains(op.transcript(), "KTQ7X9YR") ||
		!strings.Contains(op.transcript(), "https://microsoft.com/devicelogin") {
		t.Fatalf("the administrator was not shown the code and the URL they have to use:\n%s", op.transcript())
	}
}

// TestSetupRefusesToRunWithoutWhatItCannotDoWithout.
func TestSetupRefusesToRunWithoutWhatItCannotDoWithout(t *testing.T) {
	f := newAzureFake(t)
	op := &fakeOperator{t: t}

	o := setupOptions(f, op)
	o.DeploymentID = ""
	if _, err := Setup(context.Background(), o); err == nil ||
		!strings.Contains(err.Error(), "deployment ID") {
		t.Fatalf("a run with no deployment ID returned %v", err)
	}

	o = setupOptions(f, op)
	o.Say = nil
	if _, err := Setup(context.Background(), o); err == nil ||
		!strings.Contains(err.Error(), "device sign-in code") {
		t.Fatalf("a run with nowhere to show the sign-in code returned %v", err)
	}
	if len(f.login.forms) != 0 {
		t.Fatal("a refused run still signed in")
	}
}
