package main

import (
	"fmt"
	"slices"

	"github.com/0xrawsec/golang-win32/win32"
	"github.com/0xrawsec/golang-win32/win32/kernel32"
	"github.com/jimsyyap/golang_recipe/infosec_go/procinjct/winsys"

	ps "github.com/mitchellh/go-ps"
	"golang.org/x/sys/windows"
)

type SusProcess struct {
	Process     ps.Process
	SusSeverity int
}

const MEMORY_MAGIC_NUMBER uint32 = 0xA00000
const SUS_SEVERITY_LIMIT int = 10

var susProcessList []SusProcess

func main() {
	var (
		process        ps.Process
		allocatedBytes [MEMORY_MAGIC_NUMBER]byte
		numReadBytes   uintptr
		exitCode       uint32
		token          windows.Token
		luid           int64
		tokenPriv      windows.Tokenprivileges
	)

	// Get the current process's token
	errToken := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token)
	defer token.Close()
	if errToken != nil {
		return
	}

	// Get the luid of the SE_DEBUG_PRIVILEGE privilege level
	errLookup := winsys.LookupPrivilegeValue("", winsys.SE_DEBUG_NAME, &luid)
	if errLookup != nil {
		return
	}

	// Enable the SE_DEBUG_PRIVILEGE
	tokenPriv.PrivilegeCount = 1
	tokenPriv.Privileges[0].Luid.HighPart = int32(luid >> 32)
	tokenPriv.Privileges[0].Luid.LowPart = uint32(luid & 0xffffffff)
	tokenPriv.Privileges[0].Attributes = windows.SE_PRIVILEGE_ENABLED

	errAdjust := windows.AdjustTokenPrivileges(token, false, &tokenPriv, 0, nil, nil)
	if errAdjust != nil {
		return
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

			// Open process to read memory from
			handle, errOpenProcess := kernel32.OpenProcess(kernel32.PROCESS_VM_READ|kernel32.PROCESS_QUERY_INFORMATION, win32.BOOL(0), win32.DWORD(process.Pid()))
			defer kernel32.CloseHandle(handle)
			if errOpenProcess != nil {
				continue
			}

			// Get the process base address
			moduleHandles, errModules := kernel32.EnumProcessModules(handle)
			if errModules != nil {
				continue
			}

			info, errInfo := kernel32.GetModuleInformation(handle, moduleHandles[0])
			if errInfo != nil {
				continue
			}

			baseAddress := info.EntryPoint

			// Read a memorry region of the process
			_ = windows.ReadProcessMemory(windows.Handle(handle), uintptr(baseAddress), &allocatedBytes[0], uintptr(MEMORY_MAGIC_NUMBER), &numReadBytes)

			// examine the memory to determine if it's potentially a Caddy Malware
			if (uint32)(numReadBytes) == MEMORY_MAGIC_NUMBER {
				nonZeroByte := true
				for b := range allocatedBytes {
					if allocatedBytes[b] != 0 {
						nonZeroByte = false
						removeSusProcess(process.Pid())
						break
					}
				}
				if nonZeroByte {
					si := findSusProcess(process.Pid())
					if si != -1 {
						susProcessList = append(susProcessList, SusProcess{process, 1})
					} else if susProcessList[si].SusSeverity < SUS_SEVERITY_LIMIT {
						susProcessList[si].SusSeverity++
					} else if susProcessList[si].SusSeverity == SUS_SEVERITY_LIMIT {
						fmt.Printf("(%v) - (%s) Is suspected as malware!\n", process.Pid(), process.Executable())
						_ = windows.GetExitCodeProcess(windows.Handle(handle), &exitCode)
						err := windows.TerminateProcess(windows.Handle(handle), exitCode)
						if err != nil {
							fmt.Printf("(%v) - (%s) Couldn't be terminated\n", process.Pid(), process.Executable())
							susProcessList[si].SusSeverity = 1
						}
					}
				}
			} else {
				removeSusProcess(process.Pid())
			}
		}
	}
}

func findSusProcess(pid int) int {
	return slices.IndexFunc(susProcessList, func(p SusProcess) bool { return p.Process.Pid() == pid })
}

func removeSusProcess(pid int) {
	index := findSusProcess(pid)
	if index != -1 {
		susProcessList = append(susProcessList[:index], susProcessList[index+1:]...)
	}
}
