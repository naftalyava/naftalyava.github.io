---
layout: post
title: "Debugging Memory Leaks with eBPF"
date: 2024-10-26
categories: eBPF
---

# Debugging Memory Leaks with eBPF

## 1. Introduction

I recently had to track down memory leaks in a poorly written legacy application. Traditional tools like **Valgrind** weren't helpful because I needed to attach to a running executable and monitor memory allocations between two specific points in time. To solve this, I used **eBPF (extended Berkeley Packet Filter)** and **uprobes** to track every `malloc` and `free` call during that period, capturing all memory operations and identifying potential leaks.

Using `uprobes`, I hooked into functions like `malloc` and `free` in `libc`, capturing memory allocation events at the user-space level. By attaching eBPF programs to these probes, I recorded each allocation and deallocation in real time, efficiently tracking memory usage. To obtain call stacks for the leaks, I compiled the program with the `-g` and `-fno-omit-frame-pointer` flags.

This approach provided insights into the already running application that traditional tools couldn't offer. In this post, I'll show how eBPF and `uprobes` can be combined to trace memory allocations and detect leaks. You can find the full implementation, including all code and setup files, on my [GitHub repo](https://github.com/naftalyava/ebpf_and_xdp_examples/tree/main/leak_detector).

---

## 2. Prerequisites

Before diving into the code, let’s go over some essential concepts to understand the foundation of this approach.

#### **libc**
**`libc`** is the standard C library on Linux, providing essential memory management functions such as `malloc` (for allocating memory) and `free` (for deallocating memory). Most applications rely on `libc` for these operations, making it the perfect target for tracking memory usage. When a user-space program calls `malloc`, it interacts with `libc`, which handles the underlying memory requests and communicates with the kernel as needed. By hooking into `malloc` and `free`, we can effectively monitor memory allocation and deallocation events in real-time.

#### **uprobes**
**`uprobes`** (user-space probes) allow us to dynamically attach to specific functions within user-space binaries, such as `malloc` and `free` in `libc`. By doing so, we can monitor each time these functions are called, making it possible to track memory allocations and deallocations accurately. The key advantage of `uprobes` is that they don’t require any modification to the target application’s code or recompilation, making them ideal for real-time debugging.

#### **eBPF**
**eBPF** (extended Berkeley Packet Filter) is a Linux kernel technology that enables efficient, safe execution of user-defined programs within the kernel. Originally created for network packet filtering, eBPF has evolved into a versatile tool for tracing, profiling, and monitoring system activity. By using eBPF, we can gather detailed data on system and user-space events (via `uprobes`) with minimal performance overhead, making it an excellent choice for memory leak detection.

---

## 3. eBPF and Uprobes: The Foundation for User-Space Tracing

To detect memory leaks in a user-space program, we need a way to track each memory allocation and deallocation function call in `libc` over a specified time period. By combining **eBPF** with **uprobes**, we can dynamically trace these events in user-space applications with minimal performance impact, capturing every `malloc` and `free` call efficiently.

#### What is eBPF?

eBPF (extended Berkeley Packet Filter) is a powerful feature in the Linux kernel that allows developers to run custom, sandboxed programs within the kernel and user space. eBPF enables advanced monitoring, tracing, networking, and security capabilities without modifying kernel code or impacting system stability. It operates in three main areas:

- **Kernel Tracing**: eBPF can attach to kernel functions, allowing you to trace system calls, monitor kernel events, and gather performance metrics.
  
  *Example Usage*: Using **kprobes** to profile system call performance or monitor file operations.

- **User-Space Tracing**: eBPF can attach to functions in user-space applications, facilitating detailed application-level tracing and debugging without altering the application code.
  
  *Example Usage*: Utilizing **uprobes** to profile application performance or debug memory leaks.

- **Networking (XDP)**: eBPF programs can run in the **XDP (eXpress Data Path)**, processing incoming network packets before they reach the kernel's network stack. This allows for high-performance packet filtering, load balancing, and DDoS mitigation with minimal latency.
  
  *Example Usage*: Implementing custom firewalls or high-speed packet processing using XDP.

**Examples of eBPF Usage**:

- **Observability**: Tools like *bpftrace* and *bcc* leverage eBPF for deep system and application observability, providing insights into performance bottlenecks and system behavior.

- **Cilium**: A networking and security solution for Kubernetes that uses eBPF to provide features like load balancing, network policies, and transparent encryption without requiring changes to application code.

- **Debugging and Profiling**: eBPF allows developers to profile applications and the kernel in real time, helping to identify performance issues and debug complex problems efficiently.

- **Security Monitoring**: eBPF can be used to implement intrusion detection systems, monitor system calls for suspicious activity, and enforce security policies at the kernel level.

eBPF's efficiency and versatility make it an essential tool for modern Linux system administration, offering capabilities that extend across multiple domains including performance tuning, networking, security, and application debugging.

#### Understanding Uprobes
`uprobes` (user-space probes) provide a way to attach probes to specific functions or addresses in user-space applications. When a `uprobe` is attached to a function, it triggers every time the function is called. In our case, we’ll attach `uprobes` to `malloc` and `free` in `libc`. This setup allows us to capture every time the application allocates or deallocates memory through these functions, giving us the exact data needed to trace memory usage and detect leaks.

To list available `uprobes` in `libc`, we can use a `bpftrace` command like this:

```bash
sudo bpftrace -l 'uprobe:/lib/x86_64-linux-gnu/libc.so.6:*'
```

In this list, `malloc` and `free` are essential functions for tracking memory allocations and deallocations. By attaching `uprobes` to these, we can capture allocation and deallocation events in real-time, monitoring each memory operation within `libc`.

#### Combining eBPF with Uprobes
When combined, eBPF and `uprobes` allow us to dynamically trace memory allocations and deallocations across a program’s lifecycle. By attaching `uprobes` to `malloc` and `free`, we can write eBPF programs that track memory allocation events, log the requested sizes, capture stack traces, and record the memory addresses allocated.

This combination is efficient, non-intrusive, and allows us to capture all allocations and deallocations within any user-space program. Here’s how it works:
1. **`malloc` Entry**: Each time `malloc` is called, our eBPF program attached to `malloc` via `uprobes` captures the allocation size.
2. **`malloc` Exit**: When `malloc` completes, the eBPF program records the allocated memory address and captures a stack trace to pinpoint where in the code the allocation occurred.
3. **`free` Entry**: When `free` is called, our eBPF program attached to `free` via `uprobes` deletes the memory allocation entry from our tracking map.

---

## 4. Writing the eBPF Program

To trace memory allocations and deallocations, we need an eBPF program that captures information from `malloc` and `free`. This program will consist of **maps** to store allocation information and **probes** to capture memory allocation and deallocation events in real-time. 

Let’s break down the main components of this eBPF program.

#### Map Definitions
In eBPF, maps are used to store data that our program collects, making it accessible to user-space code. For our memory leak detector, we define two maps:

1. **`allocs` Map**: This map tracks each active memory allocation, using the memory address as the key and a structure with allocation details as the value.
2. **`stack_traces` Map**: This map stores stack traces for each allocation, which allows us to track the source of each memory allocation and determine where in the code each allocation originated.

Here’s how we define these maps in our eBPF program:

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64); // Memory address
    __type(value, struct alloc_info_t); // Allocation information
} allocs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 10240);
    __uint(key_size, sizeof(u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(u64));
} stack_traces SEC(".maps");
```

The `allocs` map uses the allocated memory address as the key and stores details like the allocation size and stack trace ID in a custom struct called `alloc_info_t`. The `stack_traces` map stores user-space stack traces, helping us identify where each allocation originates in the code.

#### Defining the Probes

Now, let’s look at the probes attached to `malloc` and `free`. These probes capture information at each call to `malloc` and `free` to record allocations and detect when memory is freed.

1. **`malloc_enter`**:
   - This probe captures the size of the memory allocation requested in `malloc`.
   - We use `PT_REGS_PARM1(ctx)` to retrieve the first parameter passed to `malloc`, which is the size of the memory to be allocated.

   ```c
   SEC("uprobe/malloc_enter")
   int malloc_enter(struct pt_regs *ctx) {
       u64 pid_tgid = bpf_get_current_pid_tgid();
       u64 size = PT_REGS_PARM1(ctx);

       // Save the size in a map indexed by PID/TID
       bpf_map_update_elem(&allocs, &pid_tgid, &size, BPF_ANY);
       return 0;
   }
   ```

2. **`malloc_exit`**:
   - This probe runs after `malloc` completes, capturing the returned memory address and associating it with the allocation size stored in `malloc_enter`.
   - Additionally, we capture the stack trace at this point to help trace the source of each allocation.

   ```c
   SEC("uretprobe/malloc_exit")
   int malloc_exit(struct pt_regs *ctx) {
       u64 pid_tgid = bpf_get_current_pid_tgid();
       u64 *size_ptr = bpf_map_lookup_elem(&allocs, &pid_tgid);
       if (!size_ptr) return 0;

       u64 addr = PT_REGS_RC(ctx);
       if (addr == 0) {
           bpf_map_delete_elem(&allocs, &pid_tgid);
           return 0;
       }

       int stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
       struct alloc_info_t info = {.size = *size_ptr, .stack_id = stack_id};

       bpf_map_update_elem(&allocs, &addr, &info, BPF_ANY);
       bpf_map_delete_elem(&allocs, &pid_tgid);

       return 0;
   }
   ```

3. **`free_enter`**:
   - This probe removes an allocation entry from the `allocs` map when `free` is called, ensuring we only track active allocations.
   - We retrieve the pointer being freed using `PT_REGS_PARM1(ctx)` and delete the corresponding entry from the `allocs` map.

   ```c
   SEC("uprobe/free_enter")
   int free_enter(struct pt_regs *ctx) {
       u64 addr = PT_REGS_PARM1(ctx);
       bpf_map_delete_elem(&allocs, &addr);
       return 0;
   }
   ```

Each of these probes plays a specific role:
- `malloc_enter` records the allocation size when `malloc` is called.
- `malloc_exit` captures the allocated memory address and stack trace once `malloc` completes.
- `free_enter` cleans up allocations from the map when `free` is called.

#### Compilation
Disclaimer: This code has only been tested on kernel version `6.8.0-47-generic` running on Ubuntu 22.04.
My GitHub repo includes a `Makefile` that automates the compilation of this eBPF C code. To compile, you simply need to run:

```bash
make
```

This will create an object file (`ebpf.o`) that contains the compiled eBPF code. This object file is then loaded by the Go program, which we’ll discuss next.

By defining these probes and maps, we can track all memory allocations and deallocations within a program. In the next section, we’ll look at how to implement a Go program that loads this eBPF code, attaches `uprobes`, and periodically checks for potential memory leaks.

---

## 5. Implementing the Go Program

With our eBPF program ready, the next step is to create a user-space application that loads it, attaches the probes, and periodically checks for memory leaks. Additionally, at the end of the run, the application will print all allocations that were not freed. To achieve this, we'll utilize **ebpf-go** by Cilium, a robust library for interacting with eBPF programs in Go. You can find the [ebpf-go documentation here](https://github.com/cilium/ebpf).

The Go program will handle the following tasks:

1. **Loading the eBPF Object File**: Load the compiled eBPF bytecode into the kernel.
2. **Attaching Uprobes**: Attach `uprobes` to the `malloc` and `free` functions in `libc`, enabling the eBPF program to monitor memory allocations and deallocations.
3. **Scanning for Memory Leaks**: Periodically scan the tracked allocations to identify any potential memory leaks.
4. **Reporting Leaks**: At the end of the execution, print all allocations that were not freed, providing a clear view of memory leaks.

Let’s dive into each of these components in detail.


#### Loading eBPF Objects and Maps

The first step is to load the compiled eBPF object file (`ebpf.o`) and map it to Go structures. This allows us to interact with the kernel-resident eBPF maps directly from our Go code. Here’s how we do this:

```go
package main

import (
    "log"
    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/rlimit"
)

func main() {
    // Allow the program to lock memory for eBPF maps
    if err := rlimit.RemoveMemlock(); err != nil {
        log.Fatalf("Failed to remove memlock limit: %v", err)
    }

    // Load the compiled eBPF program
    objs := struct {
        MallocEnter *ebpf.Program `ebpf:"malloc_enter"`
        MallocExit  *ebpf.Program `ebpf:"malloc_exit"`
        FreeEnter   *ebpf.Program `ebpf:"free_enter"`
        Allocs      *ebpf.Map     `ebpf:"allocs"`
        StackTraces *ebpf.Map     `ebpf:"stack_traces"`
    }{}

    if err := loadEBPFObjects(&objs, nil); err != nil {
        log.Fatalf("Failed to load eBPF objects: %v", err)
    }
    defer objs.MallocEnter.Close()
    defer objs.MallocExit.Close()
    defer objs.FreeEnter.Close()
    defer objs.Allocs.Close()
    defer objs.StackTraces.Close()
}
```

This code snippet shows how we load and map eBPF objects in Go, enabling the program to interact with kernel-level eBPF maps.

#### Attaching Uprobes

Next, we attach `uprobes` to `malloc` and `free` in `libc` so that our eBPF program can monitor these functions. We use the `link` package from the `cilium/ebpf` library to attach `uprobes` directly to the functions:

```go

func attachProbes(pid int, objs *ebpfObjects) error {
    // Locate the path to the libc library for the target process
    libcPath, err := getLibcPath(pid)
    if err != nil {
        return fmt.Errorf("failed to locate libc: %v", err)
    }

    // Attach uprobe to malloc
    mallocUprobe, err := link.OpenExecutable(libcPath).Uprobe("malloc", objs.MallocEnter, &link.UprobeOptions{PID: pid})
    if err != nil {
        return fmt.Errorf("failed to attach malloc uprobe: %v", err)
    }
    defer mallocUprobe.Close()

    // Attach uretprobe to malloc
    mallocRetUprobe, err := link.OpenExecutable(libcPath).Uretprobe("malloc", objs.MallocExit, &link.UprobeOptions{PID: pid})
    if err != nil {
        return fmt.Errorf("failed to attach malloc uretprobe: %v", err)
    }
    defer mallocRetUprobe.Close()

    // Attach uprobe to free
    freeUprobe, err := link.OpenExecutable(libcPath).Uprobe("free", objs.FreeEnter, &link.UprobeOptions{PID: pid})
    if err != nil {
        return fmt.Errorf("failed to attach free uprobe: %v", err)
    }
    defer freeUprobe.Close()

    log.Println("Attached uprobes to malloc and free.")
    return nil
}
```

In this code:
- `getLibcPath` is a helper function that finds the path to `libc` used by the target process.
- We use `link.OpenExecutable(libcPath).Uprobe()` to attach probes to `malloc` and `free`.
- `mallocUprobe` and `mallocRetUprobe` are attached to monitor entry and exit of `malloc`, capturing the allocation size, address, and stack trace.
- `freeUprobe` is attached to `free` to track deallocations and update the `allocs` map.

#### Periodic Collection of Potential Leaks

With the probes attached, the Go program sets up a timed loop to periodically scan the `allocs` map and log any active allocations that haven’t been freed. This loop acts as a garbage collection check, identifying potential memory leaks by locating entries in `allocs` without corresponding deallocations.

Here’s how we implement the periodic collection:

```go

func collectLeaksPeriodically(objs *ebpfObjects) {
    ticker := time.NewTicker(60 * time.Second)
    defer ticker.Stop()

    sigs := make(chan os.Signal, 1)
    signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
    done := make(chan bool)

    go func() {
        for {
            select {
            case <-ticker.C:
                leaks, err := collectLeaks(objs.Allocs)
                if err != nil {
                    log.Printf("Failed to collect leaks: %v", err)
                    continue
                }
                logLeaks(leaks)
            case <-sigs:
                done <- true
                return
            }
        }
    }()
    <-done
    log.Println("Stopping trace and collecting final results...")
}
```

In this snippet:
- We set up a `Ticker` to run the `collectLeaks` function every 60 seconds, which scans the `allocs` map for active allocations.
- `signal.Notify` catches termination signals (Ctrl+C), ensuring that the program stops gracefully and logs final results.
- The `collectLeaks` function retrieves each active allocation and logs any potential leaks.

---

## 6. Capturing and Resolving Stack Traces for Each Leak

Capturing stack traces for each memory allocation is crucial for identifying the origin of memory leaks. By associating each allocation with a stack trace, we can trace back to the specific function calls responsible for the allocation, which helps in pinpointing the root cause of the leak. Here’s how we capture and resolve stack traces in our eBPF program and Go code.

#### Importance of Stack Traces
Stack traces provide context on where memory allocations are occurring within the code. Each allocation in our `allocs` map includes a stack trace ID that lets us see the chain of function calls leading to the allocation. By resolving this stack trace in user space, we can see the exact sequence of function calls and identify if there’s a specific part of the code responsible for leaks.

#### Capturing Stack Traces in eBPF
In our eBPF program, the `malloc_exit` probe is responsible for capturing stack traces at the time of each allocation. We use the helper function `bpf_get_stackid` to obtain a stack trace of the current function call chain when `malloc` completes:

```c
SEC("uretprobe/malloc_exit")
int malloc_exit(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 *size_ptr = bpf_map_lookup_elem(&allocs, &pid_tgid);
    if (!size_ptr) return 0;

    u64 addr = PT_REGS_RC(ctx);
    if (addr == 0) {
        bpf_map_delete_elem(&allocs, &pid_tgid);
        return 0;
    }

    int stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
    struct alloc_info_t info = {.size = *size_ptr, .stack_id = stack_id};

    bpf_map_update_elem(&allocs, &addr, &info, BPF_ANY);
    bpf_map_delete_elem(&allocs, &pid_tgid);

    return 0;
}
```

#### Resolving Stack Traces in Go
With each allocation’s `stack_id` stored in the `allocs` map, we can retrieve and resolve these stack traces in the Go program. The `SymbolResolver` struct is responsible for mapping program counter (PC) addresses from the stack trace to function names, making the stack trace human-readable.

Here’s how we use `SymbolResolver` to resolve stack traces:

```go
func getStackTrace(stackID int32, stackTracesMap *ebpf.Map, pid int) ([]string, error) {
    if stackID < 0 {
        return nil, fmt.Errorf("invalid stack ID: %d", stackID)
    }

    var stackTrace StackTrace
    err := stackTracesMap.Lookup(stackID, &stackTrace)
    if err != nil {
        return nil, fmt.Errorf("failed to lookup stack trace: %v", err)
    }

    symResolver, err := NewSymbolResolver(fmt.Sprintf("/proc/%d/maps", pid))
    if err != nil {
        return nil, err
    }

    frames := []string{}
    for _, pc := range stackTrace {
        if pc == 0 {
            continue
        }
        sym, err := symResolver.Resolve(pc)
        if err != nil {
            frames = append(frames, fmt.Sprintf("0x%x [unknown]", pc))
        } else {
            frames = append(frames, fmt.Sprintf("0x%x %s", pc, sym))
        }
    }
    return frames, nil
}
```

In this Go code:
- We look up the `stackID` in the `stackTracesMap` to retrieve the stack trace.
- The `SymbolResolver` helps us map program counters to function names, making each frame in the stack trace readable.
- The resolved stack trace provides valuable context for each allocation, helping developers understand where memory usage originates and trace potential leaks back to their source.

---

## 7. Running the Program and Interpreting Results

With the eBPF program and Go application fully set up, we’re ready to put it to the test. In this section, we’ll go through how to run the program, capture memory allocation data, and interpret the results to identify memory leaks in the target application.

#### Running the Go Program
Our Go program takes in a few command-line arguments:
- **PID** of the target process: This specifies which process we want to trace.
- **Output file**: The file where we’ll save the results, including potential leaks and stack traces.

To start the memory leak detector, run the following command, replacing `<TARGET_PID>` with the PID of the process you want to trace:

```bash
sudo ./leak_detector -pid <TARGET_PID> -output leaks.txt
```

This command initializes the memory leak detector, attaches the probes to the target process, and begins monitoring `malloc` and `free` calls. The program will periodically log any potential memory leaks to the specified output file.

#### Interpreting Leaks with Stack Traces
Once the program has run for a suitable duration, open the output file (e.g., `leaks.txt`) to review the results. Each entry will include:
- **Leaked memory address**: The memory location where the potential leak was detected.
- **Allocation size**: The size of the leaked memory allocation.
- **Stack trace**: The recorded stack trace for each leak, showing the sequence of function calls leading to the allocation.

A sample entry in the output file might look like this:

```plaintext
Leak at address: 0x7e8231f90010, size: 149404 bytes
Stack trace:
  0x5c09ff4717ba allocateAndLeak() (/home/naftaly/dev/ebpf_and_xdp_examples/leak_detector/tests/leaky_program)
  0x5c09ff47173d workerFunction(int) (/home/naftaly/dev/ebpf_and_xdp_examples/leak_detector/tests/leaky_program)
  0x5c09ff472bd8 void std::__invoke_impl<void, void (*)(int), int>(std::__invoke_other, void (*&&)(int), int&&) (/home/naftaly/dev/ebpf_and_xdp_examples/leak_detector/tests/leaky_program)
  0x5c09ff472aee std::__invoke_result<void (*)(int), int>::type std::__invoke<void (*)(int), int>(void (*&&)(int), int&&) (/home/naftaly/dev/ebpf_and_xdp_examples/leak_detector/tests/leaky_program)
  0x5c09ff472a1f void std::thread::_Invoker<std::tuple<void (*)(int), int> >::_M_invoke<0ul, 1ul>(std::_Index_tuple<0ul, 1ul>) (/home/naftaly/dev/ebpf_and_xdp_examples/leak_detector/tests/leaky_program)
  0x5c09ff4729b4 std::thread::_Invoker<std::tuple<void (*)(int), int> >::operator()() (/home/naftaly/dev/ebpf_and_xdp_examples/leak_detector/tests/leaky_program)
  0x5c09ff472970 std::thread::_State_impl<std::thread::_Invoker<std::tuple<void (*)(int), int> > >::_M_run() (/home/naftaly/dev/ebpf_and_xdp_examples/leak_detector/tests/leaky_program)
  0x7e83216dc253 std::error_code::default_error_condition() const (/usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.30)
```

By examining the stack trace, you can pinpoint where in the code each memory leak originates. If multiple leaks appear with similar stack traces, this may indicate a recurring pattern or a specific function responsible for not freeing memory correctly.

---

## 8. Conclusion

In this post, we explored how **eBPF** and `uprobes` can be leveraged to detect memory leaks in real time by tracing memory allocations and deallocations within user-space applications. The main advantage of this method is that we can dynamically attach tracing to an already running executable without the need to run the application under traditional tools like Valgrind.

For more information on eBPF, XDP, and **ebpf-go**, refer to the [eBPF documentation](https://ebpf.io/), the [XDP documentation](https://www.kernel.org/doc/html/latest/networking/xdp.html), and the [ebpf-go documentation](https://github.com/cilium/ebpf).

For the full source code, check out the [GitHub repository](https://github.com/naftalyava/ebpf_and_xdp_examples/tree/main/leak_detector).

---
