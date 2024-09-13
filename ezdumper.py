import ida_kernwin
import ida_bytes
import ida_idaapi
import idaapi
import ida_nalt

class MemoryDumpPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_UNL
    comment = "Memory Dump Plugin"
    help = "Dumps memory from specified start to end address"
    wanted_name = "Memory Dumper"
    wanted_hotkey = "Alt-M"

    def init(self):
        return ida_idaapi.PLUGIN_OK

    def run(self, arg):
        start_addr = ida_kernwin.ask_addr(0, "Enter start address")
        end_addr = ida_kernwin.ask_addr(0, "Enter end address")
        output_file = ida_kernwin.ask_file(1, "*.bin", "Save dump as")

        if start_addr is not None and end_addr is not None and output_file:
            size = end_addr - start_addr
            data = ida_bytes.get_bytes(start_addr, size)
            
            with open(output_file, 'wb') as f:
                f.write(data)
            
            print(f"Memory dumped from 0x{start_addr:X} to 0x{end_addr:X}")
            print(f"Saved to {output_file}")
            ida_kernwin.info(f"Memory dumped successfully to {output_file}")
        else:
            ida_kernwin.warning("Operation cancelled or invalid input.")

    def term(self):
        pass

def PLUGIN_ENTRY():
    return MemoryDumpPlugin()