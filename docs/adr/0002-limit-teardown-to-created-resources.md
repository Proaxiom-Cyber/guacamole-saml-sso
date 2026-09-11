# Offer only created resources during teardown

Teardown offers only resources the deployment tool created, supported by durable
ownership records and checks against current provider state. Preserve pre-existing
resources and created resources that now support unrelated uses. Restore changes
to pre-existing settings only after interactive approval and only when no later
change conflicts with the recorded value. Preserve application data and backups
unless the administrator explicitly requests deletion.
