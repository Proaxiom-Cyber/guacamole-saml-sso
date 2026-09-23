package ui

import "errors"

var ErrBack = errors.New("back to previous configuration section")

// BackLine adds navigation only to editable configuration, never running tasks.
func (u *UI) BackLine(prompt, def string) (string, error) {
	if w := u.wizard(); w != nil {
		return w.readLineBack(prompt+"\nCtrl-B: Back to the previous section.", def, false, true)
	}
	value, err := u.Line(prompt+" (/back for previous section)", def)
	if err == nil && value == "/back" {
		return "", ErrBack
	}
	return value, err
}

// BackHiddenLine keeps recovery passphrases out of the draft and log.
func (u *UI) BackHiddenLine(prompt string) (string, error) {
	var value string
	var err error
	if u.Secret != nil {
		value, err = u.Secret(prompt)
	} else if w := u.wizard(); w != nil {
		value, err = w.readLineBack(prompt+"\nCtrl-B: Back.", "", true, true)
	} else {
		value, err = u.HiddenLine(prompt)
	}
	if err == nil {
		u.Protect(value)
	}
	return value, err
}
