# SMMAP oracle

 The orcacle keeps a global log of the number of pages that have been touched
at each checkpointing interval.  It records which pages were accessed by
putting them into the pagelist in the pagefault interceptor and protecting
them again at the checkpoint when a new checkpoint is issued. Copy-on write
should not be used.

## Interface

### Module Parameters

|Parameter| Function |
|---------|----------|
|`smmap_oracle_log_maxsize`|Sets the maximum log length |
|`smmap_log_enabled`| Disables/Enabless logging|

Memory for the log is allocated at module load-time and only if the log is enabled.

### Sysctls

|Sysctl node| Function |
|---------|----------|
|`/proc/sys/smmap/conf/oracle`  | 0: disabled, 1: record, 2: replay (Will have no effect if the `smmap_log_enabled` module parameter was not set)|
|`/proc/sys/smmap/stat/log_len` | Current length of the log |
|`/proc/sys/smmap/stat/log_last_entry`| The last log entry. Reading and writing has side-effects!|

## Usage

Logging is disabled by default.
To enable logging two module parameters have to be given when the module is
loaded: `smmap_oracle_log_maxsize=LOGENTRIES` and `smmap_oracle_log_enabled=1`.

### Recording

To put the oracle in record mode:

    echo 1 > /proc/sys/smmap/conf/oracle

Putting the oracle into recording mode will, clear and if necessary allocate
memory for the log.

### Replaying

To put the log into replay mode:

    echo 2 > /proc/sys/smmap/conf/oracle

This will reset the log position to zero but will not delete the log.

### Storing/Restoring the Log

The whole log can be stored in a stack-like manner by reading the last entry
until the log length is zero. Writing in the oracle_lastentry will cause the log
to grow by this one entry.
