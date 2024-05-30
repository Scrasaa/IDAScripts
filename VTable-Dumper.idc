
// *****************************************************************************
// - IDA Pro script 
// Name: VTable-Dumper.idc
// Desc: Dumps a .h file with the current VTable as a C class
// 
// Ver: 3.0 - May 30th, 2024 by Scrasa
// -----------------------------------------------------------------------------

#include <idc.idc>
#include <memcpy.idc>

static copy_comments()
{
	auto pAddress, iIndex;
	auto szFilePath, hFile;
	auto skipAmt;

	SetStatus(IDA_STATUS_WORK);

	// User selected vtable block
	pAddress = ScreenEA();

	if (pAddress == BADADDR)
	{
		Message("** No vtable selected! Aborted **");
		Warning("No vtable selected!\nSelect vtable block first.");
		SetStatus(IDA_STATUS_READY);
		return;
	}
	
	auto szInputClass = AskStr("", "Enter Class Name:");
	skipAmt = AskLong(1, "Number of vtable entries to ignore for indexing:");

	// Request output header file
	SetStatus(IDA_STATUS_WAITING);
	if ((szFilePath = AskFile(1, "*.h", "Select output dump file:")) == 0)
	{
		Message("Aborted.");
		SetStatus(IDA_STATUS_READY);
		return;
	}

	// And create it..
	if ((hFile = fopen(szFilePath, "wb")) != 0)
	{
		auto szFuncName, szFullName, BadHits;

		BadHits = 0;

		// Create the header
		fprintf(hFile, "// Auto reconstructed from vtable block @ 0x%08X\n// from \"%s\", modified by Scrasa\n// Don't forget to update the return type to the correct type and check if it dumped too much!\n", pAddress, GetInputFile());
		
        fprintf(hFile, "class %s \n{\npublic:\n", szInputClass);

		/* For linux, skip the first entry */
		if (Dword(pAddress) == 0)
		{
			pAddress = pAddress + 8;
		}

		pAddress = pAddress + (skipAmt * 4);
		iIndex = 0; // Initialize index

		// Loop through the vtable block
		while (pAddress != BADADDR)
		{
			auto real_addr;
			real_addr = Dword(pAddress);

			szFuncName = Name(real_addr);
			if (strlen(szFuncName) == 0)
			{
				break;
			}
			szFullName = Demangle(szFuncName, INF_LONG_DN);
			if (szFullName == "")
			{
				szFullName = szFuncName;
			}
			if (strstr(szFullName, "_ZN") != -1)
			{
				fclose(hFile);
				Warning("You must toggle GCC v3.x demangled names!\n");
				break;
			}

			auto found = strstr(szFullName, "::");
			if (found)
			{
				// Found
				auto buffer;
				// work around because idc is gay
				memcpy(buffer, szFullName, strlen(szFullName));
				auto pos = found - buffer;
				szFullName = substr(szFullName, pos+2, strlen(szFullName));
			}

			// Comment out the index numbers
			fprintf(hFile, "/*%d*/ virtual void* \t%s = 0;\n", iIndex, szFullName);
			pAddress = pAddress + 4;
			iIndex++;
		};
		
		fprintf(hFile, "};\n");
		fclose(hFile);
		Message("Successfully wrote %d vtable entries.\n", iIndex);
	}
	else
	{
		Message("** Error opening \"%s\"! Aborted **\n", szFilePath);
		Warning("Error creating \"%s\"!\n", szFilePath);
	}

	Message("\nDone.\n\n");
	SetStatus(IDA_STATUS_READY);
}

static main()
{
	copy_comments();
}
