////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//                  DiffSnake PLUGIN FOR OLLYDBG v2.01                        //
//                  written by Jan Beck                                       //
//                                                                            //
// This code is distributed "as is", without warranty of any kind, expressed  //
// or implied, including, but not limited to warranty of fitness for any      //
// particular purpose. In no event will any author of the code be liable to   //
// you for any special, incidental, indirect, consequential or any other      //
// damages caused by the use, misuse, or the inability to use of this code,   //
// including any lost profits or lost savings, even if any author of the code //
// has been advised of the possibility of such damages.                       //
// Or, translated into English: use at your own risk!                         //
//                                                                            //
// This code is free. You can modify it, include parts of it into your own    //
// programs and redistribute modified code provided that you remove all       //
// copyright messages or substitute them with your own copyright.             //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

// VERY IMPORTANT NOTICE: PLUGINS ARE UNICODE LIBRARIES! COMPILE THEM WITH BYTE
// ALIGNMENT OF STRUCTURES AND DEFAULT UNSIGNED CHAR!

// Microsoft compilers hate (and maybe justifiably) old-school functions like
// wcscpy() that may cause buffer overflow and all related dangers. Still, I
// don't want to see all these bloody warnings.
#define _CRT_SECURE_NO_DEPRECATE

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <winnt.h>                     // Only if you call ODBG2_Pluginmainloop
                                       
#include "plugin.h"

#define PLUGINNAME     L"DiffSnake"    // Unique plugin name
#define VERSION        L"1.00.00"      // Plugin version

HINSTANCE        hdllinst;             // Instance of plugin DLL

// Most of OllyDbg windows are the so called tables. A table consists of table
// descriptor (t_table) with embedded sorted data (t_table.sorted, unused in
// custom tables). If data is present, all data elements have the same size and
// begin with a 3-dword t_sorthdr: address, size, type. Data is kept sorted by
// address

typedef struct t_hitlist {
  // Obligatory header, its layout _must_ coincide with t_sorthdr!
  ulong          index;                // address of instruction hit.
  ulong          size;                 // Size of index, always 1 in our case
  ulong          type;                 // Type of entry, TY_xxx
  // Custom data follows header.
  wchar_t decodedinstruction[TEXTLEN];          // decoded operation
} t_hitlist;

static t_table   hitlisttable;              // list of addresses in hit list

t_hitlist baselist;


// Custom table function of hitlist window. Here it is used only to process
// doubleclicks (custom message WM_USER_DBLCLK). This function is also called
// on WM_DESTROY, WM_CLOSE (by returning -1, you can prevent window from
// closing), WM_SIZE (custom tables only), WM_CHAR (only if TABLE_WANTCHAR is
// set) and different custom messages WM_USER_xxx (depending on table type).
// See documentation for details.
long HitlistSelfunc(t_table *pt,HWND hw,UINT msg,WPARAM wp,LPARAM lp) {
  t_hitlist * item;
  switch (msg) {
    case WM_USER_DBLCLK:               // Doubleclick
      // Get selection.
      item=(t_hitlist *)Getsortedbyselection(&(pt->sorted),pt->sorted.selected);
      // Follow address in CPU Disassembler pane. Actual address is added to
      // the history, so that user can easily return back to it.
      if (item!=NULL) Setcpu(0,item->index,0,0,0, CPU_ASMHIST|CPU_ASMCENTER|CPU_ASMFOCUS);
      return 1;
    default: break;
  };
  return 0;
};

int Hitlistdraw(wchar_t *s,uchar *mask,int *select, t_table *pt,t_drawheader *ph,int column,void *cache) {
  int n=0;
  t_hitlist * listitem;
  // For simple tables, t_drawheader is the pointer to the data element. It
  // can't be NULL, except in DF_CACHESIZE, DF_FILLCACHE and DF_FREECACHE.
  listitem=(t_hitlist *)ph;

  switch (column) {
    case DF_CACHESIZE:                 // Request for draw cache size
      // Columns 3 and 4 (disassembly and comment) both require calls to
      // Disasm(). To accelerate processing, I call disassembler once per line
      // and cache data between the calls. Here I inform the drawing routine
      // how large the cache must be.
      return 0;//sizeof(t_disasm);
    case DF_FILLCACHE:                 // Request to fill draw cache
      // We don't need to initialize cache when drawing begins. Note that cache
      // is initially zeroed.
      break;
    case DF_FREECACHE:                 // Request to free cached resources
      // We don't need to free cached resources when drawing ends.
      break;
    case DF_NEWROW:                    // Request to start new row in window
      // New row starts. Let us disassemble the command at the pointed address.
      // I assume that bookmarks can't be set on data. First of all, we need to
      // read the contents of memory. Length of 80x86 commands is limited to
      // MAXCMDSIZE bytes.
    case 0:                            // 0-based index
	  n=Hexprint8W(s,listitem->index);//StrcopyW(s,TEXTLEN,L"%x",listitem->index);
	  memset(mask,DRAW_GRAY,n);
	  *select|=DRAW_MASK;
      break;
    case 1:   
      n=StrcopyW(s,TEXTLEN,listitem->decodedinstruction);
	  memset(mask,DRAW_GRAY,n);
	  *select|=DRAW_MASK;
      break;
    default: break;
  };
  return n;
};

////////////////////////////////////////////////////////////////////////////////
////////////////// PLUGIN MENUS EMBEDDED INTO OLLYDBG WINDOWS //////////////////

// Menu processing functions are called twice. First time (mode=MENU_VERIFY)
// OllyDbg asks to verify whether corresponding menu item applies or not. If
// necessary, menu function may change menu text (parameter name, up to TEXTLEN
// UNICODE characters). It must return one of the following codes:
//
//   MENU_ABSENT:     menu item does not apply and should not be present in
//                    the menu;
//   MENU_NORMAL:     menu item appears in the menu;
//   MENU_CHECKED:    menu item appears in the menu and has attached checkmark;
//   MENU_CHKPARENT:  menu item appears in the menu and has attached checkmark.
//                    Additionally, attaches checkmark to the parent item in
//                    menu on the previous level. This feature does not work in
//                    the main menu;
//   MENU_SHORTCUT:   menu item does not appear in the menu but is active and
//                    participates in the search for keyboard shortcut;
//   MENU_GRAYED:     item is present in the menu but disabled. This style is
//                    not compatible with OllyDbg's look-and-feel, use it only
//                    if absolutely necessary due to the menu logic.
//
// When menu item is selected (mouseclick or keyboard shortcut), menu function
// is called for the second time (mode=MENU_EXECUTE, name is undefined). At
// this moment, all threads of the debugged application are suspended. Function
// must make all necessary actions and return one of the following codes:
//
//   MENU_REDRAW:     this action has global impact, all OllyDbg windows must
//                    be updated. OllyDbg broadcasts WM_USER_CHGALL;
//   MENU_NOREDRAW:   no redrawing is necessary.
//
// If processing is lengthy and application should continue execution, use
// Resumeallthreads() at entry to the MENU_EXECUTE block and Suspendallthreads()
// on exit. Note that MENU_ABSENT and MENU_NOREDRAW are interchangeable.
//
// Parameter index allows to use single menu function with several similar menu
// items.
//
// Note that OllyDbg uses menu structuress to process keyboard shortcuts. It is
// done automatically, without the need to pay additional attention.


// Menu function of main menu, displays About dialog.
static int Mabout(t_table *pt,wchar_t *name,ulong index,int mode) {
  int n;
  wchar_t s[TEXTLEN];
  if (mode==MENU_VERIFY)
    return MENU_NORMAL;                // Always available
  else if (mode==MENU_EXECUTE) {
    // Debuggee should continue execution while message box is displayed.
    Resumeallthreads();
    // In this case, Swprintf() would be as good as a sequence of StrcopyW(),
    // but secure copy makes buffer overflow impossible.
    n=StrcopyW(s,TEXTLEN,L"DiffSnake plugin v");
    n+=StrcopyW(s+n,TEXTLEN-n,VERSION);
    // COPYRIGHT POLICY: This bookmark plugin is an open-source freeware. It's
    // just a sample. The copyright below is also just a sample and applies to
    // the unmodified sample code only. Replace or remove copyright message if
    // you make ANY changes to this code!
    n+=StrcopyW(s+n,TEXTLEN-n,L"\nCopyright none. This software is free as a bird");
    // The conditionals below are here to verify that this plugin can be
    // compiled with all supported compilers. They are not necessary in the
    // final code.
    #if defined(__BORLANDC__)
      n+=StrcopyW(s+n,TEXTLEN-n,L"\n\nCompiled with Borland (R) ");
    #elif defined(_MSC_VER)
      n+=StrcopyW(s+n,TEXTLEN-n,L"\n\nCompiled with Microsoft (R) ");
    #elif defined(__MINGW32__)
      n+=StrcopyW(s+n,TEXTLEN-n,L"\n\nCompiled with MinGW32 ");
    #else
      n+=StrcopyW(s+n,TEXTLEN-n,L"\n\nCompiled with ");
    #endif
    #ifdef __cplusplus
      StrcopyW(s+n,TEXTLEN-n,L"C++ compiler");
    #else
      StrcopyW(s+n,TEXTLEN-n,L"C compiler");
    #endif
    MessageBox(hwollymain,s,
      L"DiffSnake plugin",MB_OK|MB_ICONINFORMATION);
    // Suspendallthreads() and Resumeallthreads() must be paired, even if they
    // are called in inverse order!
    Suspendallthreads();
    return MENU_NOREDRAW;
  };
  return MENU_ABSENT;
};


// Menu function of Disassembler pane that deletes existing bookmark.
static int MMarkTrace(t_table *pt,wchar_t *name,ulong index,int mode) {
  wchar_t buffer[100];
  uchar * codeline;
  ulong codelinesize;

  if (mode==MENU_VERIFY)
    return MENU_NORMAL;                // Always available
  else if (mode==MENU_EXECUTE) {
    ulong i,j,length, declength;
    uchar cmd[MAXCMDSIZE],*decode;
	t_disasm da;
    t_reg *reg;
	t_memory *pmem;
    t_hitlist hitlistitem;
	Deletesorteddatarange(&(hitlisttable.sorted),0,0xFFFFFFFF);
	Deletesorteddatarange(&baselist,0,0xFFFFFFFF);
	for ( i=0; i<memory.sorted.n; i++) {
      pmem=(t_memory *)Getsortedbyindex(&memory.sorted,i);    // Get next memory block.
	  if ((pmem->type & MEM_GAP)!=0)
        continue;                        // Unallocated memory
      // Check whether it contains executable code.
      if ((pmem->type & (MEM_CODE|MEM_SFX))==0)
        continue;                        // Not a code   	  
	  // iterate through code
      for ( j=pmem->base; j<=pmem->base +pmem->size; j++) {
	    codeline = Finddecode(j,&codelinesize);
		if (codeline)
			if (((*codeline)&DEC_TRACED)==DEC_TRACED){
				hitlistitem.index=j;
                hitlistitem.size=1;
                hitlistitem.type=0;
                Addsorteddata(&baselist,&hitlistitem);
			}
		}
	  }
	return MENU_REDRAW;
	}
  return MENU_ABSENT;
};

static int MCompareTrace(t_table *pt,wchar_t *name,ulong index,int mode) {
  wchar_t buffer[100];
  uchar * codeline;
  ulong codelinesize;

  if (mode==MENU_VERIFY)
    return MENU_NORMAL;                // Always available
  else if (mode==MENU_EXECUTE) {
    ulong i,j,length, declength;
    uchar cmd[MAXCMDSIZE],*decode;
	t_disasm da;
    t_reg *reg;
	void * result;
	t_memory *pmem;
    t_hitlist hitlistitem;
    Deletesorteddatarange(&(hitlisttable.sorted),0,0xFFFFFFFF);
	for ( i=0; i<memory.sorted.n; i++) {
      pmem=(t_memory *)Getsortedbyindex(&memory.sorted,i);    // Get next memory block.
	  if ((pmem->type & MEM_GAP)!=0)
        continue;                        // Unallocated memory
      // Check whether it contains executable code.
      if ((pmem->type & (MEM_CODE|MEM_SFX))==0)
        continue;                        // Not a code   	  
	  // iterate through code
      for ( j=pmem->base; j<=pmem->base +pmem->size; j++) {
	    codeline = Finddecode(j,&codelinesize);
		if (codeline)
			if (((*codeline)&DEC_TRACED)==DEC_TRACED){
				result = Findsorteddata(&baselist,j,0);
				//Addtolist(result,DRAW_NORMAL,L"sorted");
				if(!result){
                  length=Readmemory(cmd,j,MAXCMDSIZE,MM_SILENT|MM_PARTIAL);
                  if (length==0) Addtolist(j,DRAW_NORMAL,L"Readmemory returned zero!");
                  decode=Finddecode(j,&declength);
                  if (decode!=NULL && declength<length) 
                     decode=NULL;
                  length=Disasm(cmd,length,j,decode,&da,DA_TEXT|DA_OPCOMM|DA_MEMORY,NULL,NULL);
                  if (length==0) Addtolist(j,DRAW_NORMAL,L"Disasm returned zero!");
                  StrcopyW(hitlistitem.decodedinstruction,TEXTLEN,da.result);
			      hitlistitem.index=j;
                  hitlistitem.size=1;
                  hitlistitem.type=0;
                  Addsorteddata(&(hitlisttable.sorted),&hitlistitem);
				}
			}
		}
	  }
	if (hitlisttable.hw==NULL){
      // Create table window. Third parameter (ncolumn) is the number of
      // visible columns in the newly created window (ignored if appearance is
      // restored from the initialization file). If it's lower than the total
      // number of columns, remaining columns are initially invisible. Fourth
      // parameter is the name of icon - as OllyDbg resource.
      Createtablewindow(&hitlisttable,0,hitlisttable.bar.nbar,NULL, L"ICO_PLUGIN",PLUGINNAME);
	}
    else
      Activatetablewindow(&hitlisttable);
	return MENU_REDRAW;
	}
  return MENU_ABSENT;
};


// Plugin menu that will appear in the main OllyDbg menu. Note that this menu
// must be static and must be kept for the whole duration of the debugging
// session.
static t_menu mainmenu[] = {
  { L"Take baseline",
       L"Make note of all the addresses that have been marked by the Hit Trace",
       K_NONE, MMarkTrace, NULL, 0 },
  { L"Show Diff",
       L"Show all instructions that have been executed since last baseline",
       K_NONE, MCompareTrace, NULL, 0 },
  { L"|About",
       L"About Bookmarks plugin",
       K_NONE, Mabout, NULL, 0 },
  { NULL, NULL, K_NONE, NULL, NULL, 0 }
};

// Plugin menu that will appear in the Disassembler pane of CPU window.
static t_menu disasmmenu[] = {
  // Menu items that set new bookmarks
  { L"Take baseline", L"Make note of all the addresses that have been marked by the Hit Trace", K_NONE, MMarkTrace, NULL, 0 },
  { L"Show Diff",     L"Show all instructions that have been executed since last baseline", K_NONE, MCompareTrace, NULL, 0 },
  // End of menu.
  { NULL, NULL, K_NONE, NULL, NULL, 0 }
};


// Adds items either to main OllyDbg menu (type=PWM_MAIN) or to popup menu in
// one of the standard OllyDbg windows, like PWM_DISASM or PWM_MEMORY. When
// type matches, plugin should return address of menu. When there is no menu of
// given type, it must return NULL. If menu includes single item, it will
// appear directly in menu, otherwise OllyDbg will create a submenu with the
// name of plugin. Therefore, if there is only one item, make its name as
// descriptive as possible.
extc t_menu * __cdecl ODBG2_Pluginmenu(wchar_t *type) {
  if (wcscmp(type,PWM_MAIN)==0)
    // Main menu.
    return mainmenu;
  else if (wcscmp(type,PWM_DISASM)==0)
    // Disassembler pane of CPU window.
    return disasmmenu;
  return NULL;                         // No menu
};

// Entry point of the plugin DLL. Many system calls require DLL instance
// which is passed to DllEntryPoint() as one of parameters. Remember it. Do
// not make any initializations here, preferrable way is to place them into
// ODBG_Plugininit() and cleanup in ODBG_Plugindestroy().
BOOL WINAPI DllEntryPoint(HINSTANCE hi,DWORD reason,LPVOID reserved) {
  if (reason==DLL_PROCESS_ATTACH)
    hdllinst=hi;                       // Mark plugin instance
  return 1;                            // Report success
};

// ODBG2_Pluginquery() is a "must" for valid OllyDbg plugin. It must check
// whether given OllyDbg version is correctly supported, and return 0 if not.
// Then it should fill plugin name and plugin version (as UNICODE strings) and
// return version of expected plugin interface. If OllyDbg decides that this
// plugin is not compatible, it will be unloaded. Plugin name identifies it
// in the Plugins menu. This name is max. 31 alphanumerical UNICODE characters
// or spaces + terminating L'\0' long. To keep life easy for users, name must
// be descriptive and correlate with the name of DLL. Parameter features is
// reserved for the future. I plan that features[0] will contain the number
// of additional entries in features[]. Attention, this function should not
// call any API functions: they may be incompatible with the version of plugin!
extc int __cdecl ODBG2_Pluginquery(int ollydbgversion,ulong *features,
  wchar_t pluginname[SHORTNAME],wchar_t pluginversion[SHORTNAME]) {
  // Check whether OllyDbg has compatible version. This plugin uses only the
  // most basic functions, so this check is done pro forma, just to remind of
  // this option.
  if (ollydbgversion<201)
    return 0;
  // Report name and version to OllyDbg.
  wcscpy(pluginname,PLUGINNAME);       // Name of plugin
  wcscpy(pluginversion,VERSION);       // Version of plugin
  return PLUGIN_VERSION;               // Expected API version
};

// Optional entry, called immediately after ODBG2_Pluginquery(). Plugin should
// make one-time initializations and allocate resources. On error, it must
// clean up and return -1. On success, it must return 0.
extc int __cdecl ODBG2_Plugininit(void) {
  // Data contains no resources, so destructor is
  // not necessary. (Destructor is called each time data item is removed from
  // the sorted data). 	
	  // create list of hit addresses
      if (Createsorteddata(
                       &baselist,                // Descriptor of sorted data
                       sizeof(t_hitlist),                // Size of single data item
                       10,                                // Initial number of allocated items
                       NULL,//(SORTFUNC *)Bookmarksortfunc,      // Sorting function
                       NULL,//(DESTFUNC *)Bookmarkdestfunc,      // Data destructor
                       0)!=0)                             // Simple data, no special options
        return -1;
	  // create list of differential hit addresses
      if (Createsorteddata(
                       &(hitlisttable.sorted),                // Descriptor of sorted data
                       sizeof(t_hitlist),                // Size of single data item
                       10,                                // Initial number of allocated items
                       NULL,//(SORTFUNC *)Bookmarksortfunc,      // Sorting function
                       NULL,//(DESTFUNC *)Bookmarkdestfunc,      // Data destructor
                       0)!=0)                             // Simple data, no special options
        return -1;
      wcscpy(hitlisttable.name,L"Hit Trace Difference");
      hitlisttable.mode=TABLE_SAVEALL;
      hitlisttable.bar.visible=1;
      hitlisttable.bar.name[0]=L"Address";
      hitlisttable.bar.expl[0]=L"Address of instruction";
      hitlisttable.bar.mode[0]=BAR_FLAT;
      hitlisttable.bar.defdx[0]=9;
      hitlisttable.bar.name[1]=L"Instruction";
      hitlisttable.bar.expl[1]=L"Decoded Instruction";
      hitlisttable.bar.mode[1]=BAR_FLAT;
      hitlisttable.bar.defdx[1]=80;
      hitlisttable.bar.nbar=2;
      hitlisttable.tabfunc=HitlistSelfunc;
      hitlisttable.custommode=0;
      hitlisttable.customdata=NULL;
      hitlisttable.updatefunc=NULL;
      hitlisttable.drawfunc=(DRAWFUNC *)Hitlistdraw;
      hitlisttable.tableselfunc=NULL;
      hitlisttable.menu=NULL;

  // Report success.
  return 0;
};

// Function is called when user opens new or restarts current application.
// Plugin should reset internal variables and data structures to the initial
// state.
extc void __cdecl ODBG2_Pluginreset(void) {
  Deletesorteddatarange(&(hitlisttable.sorted),0,0xFFFFFFFF);
};


////////////////////////////////////////////////////////////////////////////////
/////////////////////////////// DUMP WINDOW HOOK ///////////////////////////////

// Dump windows display contents of memory or file as bytes, characters,
// integers, floats or disassembled commands. Plugins have the option to modify
// the contents of the dump windows. If ODBG2_Plugindump() is present and some
// dump window is being redrawn, this function is called first with column=
// DF_FILLCACHE, addr set to the address of the first visible element in the
// dump window and n to the estimated total size of the data displayed in the
// window (n may be significantly higher than real data size for disassembly).
// If plugin returns 0, there are no elements that will be modified by plugin
// and it will receive no other calls. If necessary, plugin may cache some data
// necessary later. OllyDbg guarantees that there are no calls to
// ODBG2_Plugindump() from other dump windows till the final call with
// DF_FREECACHE.
// When OllyDbg draws table, there is one call for each table cell (line/column
// pair). Parameters s (UNICODE), mask (DRAW_xxx) and select (extended DRAW_xxx
// set) contain description of the generated contents of length n. Plugin may
// modify it and return corrected length, or just return the original length.
// When table is completed, ODBG2_Plugindump() receives final call with
// column=DF_FREECACHE. This is the time to free resources allocated on
// DF_FILLCACHE. Returned value is ignored.
// Use this feature only if absolutely necessary, because it may strongly
// impair the responsiveness of the OllyDbg. Always make it switchable with
// default set to OFF!
extc int _export cdecl ODBG2_Plugindump(t_dump *pd, wchar_t *s,uchar *mask,int n,int *select,ulong addr,int column) {
  int i=0;
  wchar_t w[TEXTLEN];
  void * result;
  if (column==DF_FILLCACHE) {
    // Check if there are any trace diffs to annotate at all
    if (hitlisttable.sorted.n==0)
      return 0;                        // empty diff means no annotations to do
    // Check whether it's Disassembler pane of the CPU window.
    if (pd==NULL || (pd->menutype & DMT_CPUMASK)!=DMT_CPUDASM)
      return 0;                        // Not a Disassembler
    // Just for the sake, assure that bookmarks apply: not a file dump, not a
    // backup display
    if (pd->filecopy!=NULL ||
      (pd->dumptype & DU_TYPEMASK)!=DU_DISASM ||
      (pd->dumptype & DU_BACKUP)!=0)
      return 0;                        // Invalid dump type
    // if we got to here return 1 to indicate that we want to annotate the second column
    return 1; }                        // No bookmarks to display
  else if (column==2) {
    // Check whether there is a bookmark. Note that there may be several marks
    // on the same address!
    result = Findsorteddata(&(hitlisttable.sorted),addr,0);
    if (result==0)
      return n;                        // No diff hits on address
    // Skip graphical symbols (loop brackets).(count number of graphical symbols at beginning of line
    for (i=0; i<n; i++) {
      if ((mask[i] & DRAW_GRAPH)==0) break; };
    // Insert text.
    mask[0]=DRAW_GRAPH;
	s[0]=G_BIGPOINT;
  }
  else if (column==DF_FREECACHE) {
    // We have allocated no resources, so we have nothing to do here.
  };
  return n;
};
