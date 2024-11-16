package main

import (
	"fmt"
	"slices"
	"syscall"
	"unsafe"

	"github.com/jimsyyap/golang_recipe/infosec_go/procinjct/winsys"

	ps "github.com/mitchellh/go-ps"
	"golang.org/x/sys/windows"
)

type HeapSpecification struct {
	Size      uint64
	ProcessId uint32
	HeapId    uintptr
	Flags     uint32
}

type SusProcess struct {
	Process     ps.Process
	SusSeverity int
}

var (
	susProcessList []SusProcess

	// Standard kerenl32 go package doesn't implement Heap read of other processes so we load the dll directly to the program
	kernel32dll = syscall.NewLazyDLL("kernel32.dll")
)

const (
	MEMORY_MAGIC_NUMBER    uint32 = 0xA00000 // 10MB
	SUS_SEVERITY_THRESHOLD int    = 10       // Highest severity score - treated as malware
)

func main() {
	var (
		process    ps.Process
		memBuffer  [MEMORY_MAGIC_NUMBER]byte
		numReadMem uintptr
	)

	var heap32ListNext = kernel32dll.NewProc("Heap32ListNext")

	heap := HeapSpecification{
		Size: uint64(unsafe.Sizeof(HeapSpecification{})),
	}

	errPriv := EnablePrivilage(winsys.SE_DEBUG_NAME)
	if errPriv != nil {
		fmt.Println("Error adjusting token", errPriv)
	}

	fmt.Println("Scanning processes to find Caddy...")

	for {
		// List the running processes
		processList, err := ps.Processes()
		if err != nil {
			fmt.Println("This program only works on windows systems")
			return
		}

		for i := range processList {
			process = processList[i]

			// Get snapshot of the current process so we won't examine it while it may be changed
			hSnapShot, errCreateSnapshot := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPHEAPLIST, uint32(process.Pid()))
			defer windows.CloseHandle(hSnapShot)
			if errCreateSnapshot != nil {
				continue
			}

			if errHeapSpecification := GetProcessFirstHeap(syscall.Handle(hSnapShot), &heap); errHeapSpecification != nil {
				continue
			}

			hProcess, errOpenProcess := windows.OpenProcess(windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_TERMINATE, false, uint32(process.Pid()))
			defer windows.CloseHandle(hProcess)
			if errOpenProcess != nil {
				continue
			}

			for {
				baseAddress := heap.HeapId // Heap id is the base address

				errReadHeap := windows.ReadProcessMemory(hProcess, baseAddress, &memBuffer[0], uintptr(MEMORY_MAGIC_NUMBER), &numReadMem)
				if errReadHeap != nil && numReadMem == 0 {
					break
				}

				// Examine the memory to determine if it's potentially a Caddy Malware
				if (uint32)(numReadMem) == MEMORY_MAGIC_NUMBER {
					if IsLMEM_ZEROINIT(memBuffer) {
						si := FindSusProcess(process.Pid())
						if si == -1 {
							susProcessList = append(susProcessList, SusProcess{process, 1})
						} else if susProcessList[si].SusSeverity < SUS_SEVERITY_THRESHOLD {
							susProcessList[si].SusSeverity++
							fmt.Printf("Raising suspicion on (%v) - (%s) [SEVERITY: %v]\n", process.Pid(), process.Executable(), susProcessList[si].SusSeverity)
						} else if susProcessList[si].SusSeverity == SUS_SEVERITY_THRESHOLD {
							fmt.Printf("(%v) - (%s) Is suspected as malware!\n", process.Pid(), process.Executable())
							errKill := KillProcess(hProcess)
							if errKill != nil {
								fmt.Printf("(%v) - (%s) Couldn't be terminated\n", process.Pid(), process.Executable())
							}
						}
					} else {
						RemoveSusProcess(process.Pid())
					}
				} else {
					RemoveSusProcess(process.Pid())
				}

				// Proceed to next heap
				heapFound, _, _ := heap32ListNext.Call(uintptr(hSnapShot), uintptr(unsafe.Pointer(&heap)))
				if heapFound == 0 {
					break
				}
			}
		}
	}
}

func EnablePrivilage(privilege string) (err error) {
	var (
		cToken    windows.Token
		luid      int64
		tokenPriv windows.Tokenprivileges
	)

	// Get the current process's token
	errToken := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &cToken)
	defer cToken.Close()
	if errToken != nil {
		return errToken
	}

	// Get the luid of the SE_DEBUG_PRIVILEGE privilege level
	errLookup := winsys.LookupPrivilegeValue("", privilege, &luid)
	if errLookup != nil {
		return errLookup
	}

	// Enable the SE_DEBUG_PRIVILEGE
	// Note. to assign the LUID implementation of windows we had to unpack the LUID implementation of winsys of type int64 to 2 parts of int32.
	// First we shift 32 bits to the right to get the high part.
	// Then we effectively zero out all bits that are outsize of the 32 bits of luid to get the low part.
	tokenPriv.PrivilegeCount = 1
	tokenPriv.Privileges[0].Luid.HighPart = int32(luid >> 32)
	tokenPriv.Privileges[0].Luid.LowPart = uint32(luid & 0xffffffff)
	tokenPriv.Privileges[0].Attributes = windows.SE_PRIVILEGE_ENABLED

	errAdjust := windows.AdjustTokenPrivileges(cToken, false, &tokenPriv, 0, nil, nil)
	if errAdjust != nil {
		return errAdjust
	}

	return nil
}

func GetProcessFirstHeap(handle syscall.Handle, heap *HeapSpecification) (err error) {
	var heap32ListFirst = kernel32dll.NewProc("Heap32ListFirst")

	heapFound, _, errHeap := heap32ListFirst.Call(uintptr(handle), uintptr(unsafe.Pointer(heap)))
	if heapFound == 0 {
		return errHeap
	}

	return nil
}

func IsLMEM_ZEROINIT(memBuffer [MEMORY_MAGIC_NUMBER]byte) bool {
	for b := range memBuffer {
		if memBuffer[b] != 0 {
			return false
		}
	}

	return true
}

func KillProcess(hProcess windows.Handle) (err error) {
	var exitCode uint32

	errExitCode := windows.GetExitCodeProcess(hProcess, &exitCode)
	if errExitCode != nil {
		return errExitCode
	}

	errTerminate := windows.TerminateProcess(hProcess, exitCode)
	if errTerminate != nil {
		return errTerminate
	}

	return nil
}

func FindSusProcess(pid int) int {
	return slices.IndexFunc(susProcessList, func(p SusProcess) bool { return p.Process.Pid() == pid })
}

func RemoveSusProcess(pid int) {
	index := FindSusProcess(pid)
	if index != -1 {
		susProcessList = append(susProcessList[:index], susProcessList[index+1:]...)
	}
}
