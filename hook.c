#include<ntddk.h>

//struktura opisująca SSDT
typedef struct _SERVICE_DESCRIPTOR_TABLE
{
  PVOID   ServiceTableBase; //adres tablicy
  PULONG  ServiceCounterTableBase; //nieużywane
  ULONG   NumberOfService; //liczba syscalli
  ULONG   ParamTableBase; //nie interesuje nas to
} SERVICE_DESCRIPTOR_TABLE, *PSERVICE_DESCRIPTOR_TABLE; 
extern PSERVICE_DESCRIPTOR_TABLE    KeServiceDescriptorTable;//KeServiceDescriptorTable - exportowane funkcje 


VOID Hook();
VOID UnHook();
VOID OnUnload(IN PDRIVER_OBJECT DriverObject);

ULONG JmpAddress; //adres NtOpenProccess
ULONG OldServiceAddress;//oryginalny NtOpenProcess 

__declspec(naked) NTSTATUS __stdcall NewNtOpenProcess(PHANDLE ProcessHandle,
               ACCESS_MASK DesiredAccess,
               POBJECT_ATTRIBUTES ObjectAttributes,
               PCLIENT_ID ClientId) 
{
  DbgPrint("NewNtOpenProcess() został wywołany");
  //UnHook(); //bez tego wywoływana jest pętla
  __asm{
    push    0C4h
    push    804eb560h  //10 bajtów
    jmp     [JmpAddress] //   
  }
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject,PUNICODE_STRING RegistryPath)
{
  DriverObject->DriverUnload = OnUnload; //pozwala na dynamiczne "odładowanie" sterownika
  DbgPrint("Hooker loaded");
  Hook();
  return STATUS_SUCCESS;
}

VOID OnUnload(IN PDRIVER_OBJECT DriverObject)
{
  DbgPrint("Hooker unloaded!");
  UnHook();
}
//podmień adres
VOID Hook()
{
  ULONG Address;
  ULONG SSDTAddress = (ULONG)KeServiceDescriptorTable->ServiceTableBase;
  DbgPrint("Adres SSDT: 0x%lx\n", SSDTAddress);
  
  Address = (ULONG)KeServiceDescriptorTable->ServiceTableBase + 0x7A * 4;//0x7A to offset NtOpenProccess
  OldServiceAddress = *(ULONG*)Address;//zachowaj oryginalny adres, aby go potem przywrócić
  DbgPrint("Stary Adres NtOpenProccess:0x%lx",OldServiceAddress);
  DbgPrint("Nowy Adres NtOpenProcess:0x%lx",NewNtOpenProcess);

  JmpAddress = (ULONG)NtOpenProcess + 10; //skocz do NtOpenProccess + 10 (+10 bo na stosie znajdują się już argumenty do wywołania call'a funkcji)
  DbgPrint("JmpAddress:0x%lx",JmpAddress-10);
    
  __asm{	//wyłączamy ochronę pamięci
    push ebx
    mov  ebx,cr0
    and  ebx, 0xFFFEFFFF
    mov  cr0,ebx
	pop ebx
  }

  *((ULONG*)Address) = (ULONG)NewNtOpenProcess;	//zakładamy hook'a
  DbgPrint("Hooked!");

  __asm{	//włączamy ochronę pamięci
    push ebx
    mov  ebx,cr0
    or  ebx, 0x00010000
    mov  cr0,ebx
	pop ebx
  }
}

// przywróć oryginalny adres
VOID UnHook()
{
  ULONG Address;
  Address = (ULONG)KeServiceDescriptorTable->ServiceTableBase + 0x7A*4;	//znajdź adres funkcji w tablicy


  __asm{	//wyłączamy ochronę pamięci
    push ebx
    mov  ebx,cr0
    and  ebx, 0xFFFEFFFF
    mov  cr0,ebx
	pop ebx
  }

  *((ULONG*)Address) = (ULONG)OldServiceAddress; //przywracamy adres starej funkcji

  __asm{	//włączamy ochronę pamięci
    push ebx
    mov  ebx,cr0
    or  ebx, 0x00010000
    mov  cr0,ebx
	pop ebx
  }

  DbgPrint("Unhooked!");
}