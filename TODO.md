* manpage for ratools/rad and ratools/racomplete-ractl

* Implement this:

        Note that system management may disable a router's IP forwarding
        capability (i.e., changing the system from being a router to being a
        host), a step that does not necessarily imply that the router's
        interfaces stop being advertising interfaces.  In such cases,
        subsequent Router Advertisements MUST set the Router Lifetime field
        to zero.
        (RFC 4861 Sec. 6.2.5.  Ceasing To Be an Advertising Interface)

 This would imply checking proc on a regular basis. Polling is bad. What now?


* Integration with systemd, sd_booted(), sd_journal_*()


* Check ALL THE pointers for their _required_ mutability. Many of them are
  too permissive. Add const keyword when possible.

* Write file CODING_STYLE where we explain the ratools coding guidelines
