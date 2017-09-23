# Hook the continue command to check whether the user is trying to
# allow execution of the process during a rollback. If so, the plugin
# will send a restore command, de-facto forcing the restore before
# execution.
define hook-continue
    set $ignoreval = $dl_force_restore()
end

# Perform the cleanup before the process shuts down.
define hook-run
    set $ignoreval = $dl_reset()
end
