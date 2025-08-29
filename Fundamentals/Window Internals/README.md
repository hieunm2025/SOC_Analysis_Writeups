# Windows Internal
Processes: a container of set of resources used when executing an instance of program. 

Components:
- A private virtual address space
- A executable program
- A list of open handles
- A security context: An access token identifying the user, security groups, privileges, and other security-related information associated with the process.
- A process ID (PID):  a unique identifier, part of an internal cliend ID
- At least one thread of execution: If a process shows zero threads in task manager, it usually indicates a problem preventing its delection often due to buggy driver code.

Thread : an entity within a process that Windows schedules for execution; without it


