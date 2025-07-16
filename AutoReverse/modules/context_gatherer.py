"""
Context Gatherer for AutoReverse Plugin
Collects comprehensive context about functions including callers, disassembly, and pseudocode
Based on advanced reverse engineering analysis patterns
"""

import ida_name
import ida_bytes
import ida_typeinf
import ida_frame
import ida_funcs
import idaapi
import ida_xref
import ida_hexrays
import idc
import idautils
from typing import Optional, List, Dict, Any
import ida_segment

class ContextGatherer:
    """Gathers comprehensive context for function analysis"""
    
    def __init__(self):
        self.has_hexrays = self._check_hexrays()
        self._xref_type_map = {
            ida_xref.fl_CF: "Call (Far)", 
            ida_xref.fl_CN: "Call (Near)",
            ida_xref.fl_JF: "Jump (Far)", 
            ida_xref.fl_JN: "Jump (Near)",
            ida_xref.fl_F:  "Ordinary Flow",
            ida_xref.dr_O: "Offset To", 
            ida_xref.dr_W: "Write To",
            ida_xref.dr_R: "Read To",   
            ida_xref.dr_T: "Text To (Name)",
            ida_xref.dr_I: "Info To (Struct)",
        }
    
    def _check_hexrays(self) -> bool:
        """Check if Hex-Rays is available"""
        try:
            return bool(ida_hexrays.get_hexrays_version())
        except Exception:
            return False
    
    def get_name_at_ea(self, ea: int) -> str:
        """Get a meaningful name for an address"""
        if ea == idaapi.BADADDR:
            return "BADADDR"
        
        name = idc.get_name(ea, ida_name.GN_VISIBLE | ida_name.GN_DEMANGLED)
        func = ida_funcs.get_func(ea)
        
        if name and not name.startswith("sub_"):
            if func and func.start_ea != ea:
                base = idc.get_name(func.start_ea)
                return f"{base}+0x{ea - func.start_ea:X}"
            return name
        
        if func:
            base = idc.get_func_name(func.start_ea)
            if not base or base.startswith("sub_"):
                base = f"sub_{func.start_ea:X}"
            if func.start_ea != ea:
                return f"{base}+0x{ea - func.start_ea:X}"
            return base
        
        return name or f"unk_{ea:X}"
    
    def get_disassembly_lines(self, ea: int, max_lines: Optional[int] = None, 
                            highlight_ea: Optional[int] = None, include_header: bool = False) -> str:
        """Get disassembly lines for a function"""
        try:
            lines = []
            count = 0
            
            func = ida_funcs.get_func(ea)
            start = func.start_ea if func else ea
            end = func.end_ea if func else idaapi.BADADDR
            
            if include_header and func:
                lines.append(f"; Function: {self.get_name_at_ea(start)}")
            
            # Ensure we have valid addresses
            if start == idaapi.BADADDR or end == idaapi.BADADDR:
                return f"Invalid address range: start=0x{start:X}, end=0x{end:X}"
            
            for head in idautils.Heads(start, end):
                if max_lines and count >= max_lines:
                    lines.append("...")
                    break
                
                try:
                    disasm = idc.generate_disasm_line(head, 0) or '???'
                    prefix = "  -> " if head == highlight_ea else ""
                    lines.append(f"{prefix}0x{head:X}: {disasm}")
                    count += 1
                except Exception as e:
                    lines.append(f"0x{head:X}: <disassembly error: {e}>")
                    count += 1
            
            if not lines:
                return f"No disassembly available for address 0x{ea:X}"
            
            return "\n".join(lines)
            
        except Exception as e:
            print(f"Error in get_disassembly_lines: {e}")
            return f"Disassembly error: {e}"
    
    def get_pseudocode_str(self, ea: int) -> str:
        """Get pseudocode for a function"""
        if not self.has_hexrays:
            return "Hex-Rays decompiler not available"
        
        try:
            func = ida_funcs.get_func(ea)
            if not func:
                return "Address not in function"
            
            cfunc = ida_hexrays.decompile(func.start_ea)
            if not cfunc:
                return "Decompilation failed"
            
            return "\n".join(idaapi.tag_remove(s.line) for s in cfunc.get_pseudocode())
        except Exception as e:
            return f"Pseudocode error: {e}"
    
    def get_xref_type_description(self, xref_obj) -> str:
        """Get human-readable description of xref type"""
        type_str = self._xref_type_map.get(xref_obj.type)
        if not type_str:
            if xref_obj.iscode:
                type_str = f"Code Ref (Type {xref_obj.type})"
            else:
                type_str = f"Data Ref (Type {xref_obj.type})"
        
        if xref_obj.user:
            type_str += " (User)"
        
        return type_str
    
    def gather_function_context(self, ea: int, max_disasm_lines: int = 100, 
                              max_caller_lines: int = 50, max_callers: int = 10) -> Dict[str, Any]:
        """Gather comprehensive context for a function"""
        func = ida_funcs.get_func(ea)
        if not func:
            return {"error": "Address not in function"}
        
        # Ensure we're at function start
        func_ea = func.start_ea
        func_name = self.get_name_at_ea(func_ea)
        
        # Initialize context with safe defaults
        context = {
            "function_name": func_name,
            "function_address": f"0x{func_ea:X}",
            "function_size": func.end_ea - func.start_ea,
            "disassembly": "",
            "pseudocode": "",
            "callers": [],
            "calls_made": []
        }
        
        # Safely gather disassembly
        try:
            context["disassembly"] = self.get_disassembly_lines(func_ea, max_disasm_lines, None, True)
        except Exception as e:
            print(f"Error getting disassembly for {func_name}: {e}")
            context["disassembly"] = f"Disassembly unavailable: {e}"
        
        # Safely gather pseudocode
        try:
            context["pseudocode"] = self.get_pseudocode_str(func_ea)
        except Exception as e:
            print(f"Error getting pseudocode for {func_name}: {e}")
            context["pseudocode"] = f"Pseudocode unavailable: {e}"
        
        # Safely get all xrefs to this function (who calls this function)
        xrefs_to = []
        try:
            xrefs_to = [x for x in idautils.XrefsTo(func_ea, ida_xref.XREF_ALL) 
                       if x.frm != idaapi.BADADDR]
        except Exception as e:
            print(f"Error getting XREFs TO for {func_name}: {e}")
        
        # Safely get all xrefs from this function (what this function calls)
        xrefs_from = []
        try:
            for head in idautils.Heads(func.start_ea, func.end_ea):
                for xref in idautils.XrefsFrom(head, ida_xref.XREF_ALL):
                    if xref.to != idaapi.BADADDR and xref.to != head:
                        # Only include actual external function calls, not internal flow
                        # Skip if target is within the same function
                        if func.start_ea <= xref.to < func.end_ea:
                            continue
                        
                        # Only include actual calls, not ordinary flow or data references
                        if xref.type not in [ida_xref.fl_CF, ida_xref.fl_CN]:  # Call Far, Call Near
                            continue
                        
                        # Check if target is actually a function
                        target_func = ida_funcs.get_func(xref.to)
                        if not target_func:
                            continue
                        
                        xrefs_from.append((head, xref))
        except Exception as e:
            print(f"Error getting XREFs FROM for {func_name}: {e}")
        
        # Process calls made by this function
        called_funcs = set()
        for call_site, xref in xrefs_from:
            try:
                target_name = self.get_name_at_ea(xref.to)
                xref_type = self.get_xref_type_description(xref)
                
                call_info = {
                    "target_name": target_name,
                    "target_address": f"0x{xref.to:X}",
                    "call_site": f"0x{call_site:X}",
                    "xref_type": xref_type,
                    "disassembly": "",
                    "pseudocode": ""
                }
                
                # Get detailed analysis of called function
                target_func = ida_funcs.get_func(xref.to)
                if target_func and target_func.start_ea not in called_funcs:
                    try:
                        call_info["disassembly"] = self.get_disassembly_lines(
                            target_func.start_ea, max_caller_lines, xref.to, True)
                    except Exception as e:
                        call_info["disassembly"] = f"Disassembly error: {e}"
                    
                    try:
                        call_info["pseudocode"] = self.get_pseudocode_str(target_func.start_ea)
                    except Exception as e:
                        call_info["pseudocode"] = f"Pseudocode error: {e}"
                    
                    called_funcs.add(target_func.start_ea)
                elif target_func and target_func.start_ea in called_funcs:
                    call_info["note"] = "Already analyzed above"
                else:
                    # Not a function, get limited context
                    try:
                        call_info["disassembly"] = self.get_disassembly_lines(
                            xref.to, 15, xref.to, False)
                    except Exception as e:
                        call_info["disassembly"] = f"Disassembly error: {e}"
                    
                    call_info["note"] = "Not in function"
                
                context["calls_made"].append(call_info)
            except Exception as e:
                print(f"Error processing call from {call_site:X} to {xref.to:X}: {e}")
                context["calls_made"].append({
                    "target_name": f"<error: {e}>",
                    "target_address": f"0x{xref.to:X}",
                    "call_site": f"0x{call_site:X}",
                    "xref_type": "Error",
                    "disassembly": "",
                    "pseudocode": "",
                    "note": f"Failed to process called function: {e}"
                })
        
        # Process callers of this function
        if not xrefs_to:
            context["callers_info"] = "No callers found"
        
        dumped_funcs = set()
        caller_count = 0
        
        for xref in sorted(xrefs_to, key=lambda x: x.frm):
            try:
                # Limit number of callers to prevent excessive context
                if caller_count >= max_callers:
                    remaining = len(xrefs_to) - caller_count
                    context["callers"].append({
                        "name": f"... and {remaining} more callers",
                        "address": "N/A",
                        "xref_type": "Truncated",
                        "disassembly": "",
                        "pseudocode": "",
                        "note": f"Context truncated to prevent API limits. {remaining} additional callers not shown."
                    })
                    break
                    
                caller_ea = xref.frm
                caller_name = self.get_name_at_ea(caller_ea)
                xref_type = self.get_xref_type_description(xref)
                
                caller_info = {
                    "name": caller_name,
                    "address": f"0x{caller_ea:X}",
                    "xref_type": xref_type,
                    "disassembly": "",
                    "pseudocode": ""
                }
                
                caller_func = ida_funcs.get_func(caller_ea)
                if caller_func:
                    # Don't duplicate analysis of same function
                    if caller_func.start_ea in dumped_funcs:
                        caller_info["note"] = "Already analyzed above"
                    else:
                        try:
                            caller_info["disassembly"] = self.get_disassembly_lines(
                                caller_func.start_ea, max_caller_lines, caller_ea, True)
                        except Exception as e:
                            caller_info["disassembly"] = f"Disassembly error: {e}"
                        
                        try:
                            caller_info["pseudocode"] = self.get_pseudocode_str(caller_func.start_ea)
                        except Exception as e:
                            caller_info["pseudocode"] = f"Pseudocode error: {e}"
                        
                        dumped_funcs.add(caller_func.start_ea)
                else:
                    # Not in function, get limited context
                    try:
                        caller_info["disassembly"] = self.get_disassembly_lines(
                            caller_ea, 15, caller_ea, False)
                    except Exception as e:
                        caller_info["disassembly"] = f"Disassembly error: {e}"
                    
                    try:
                        caller_info["pseudocode"] = self.get_pseudocode_str(caller_ea)
                    except Exception as e:
                        caller_info["pseudocode"] = f"Pseudocode error: {e}"
                    
                    caller_info["note"] = "Not in function"
                
                context["callers"].append(caller_info)
                caller_count += 1
                
            except Exception as e:
                print(f"Error processing caller at {xref.frm:X}: {e}")
                context["callers"].append({
                    "name": f"<error: {e}>",
                    "address": f"0x{xref.frm:X}",
                    "xref_type": "Error",
                    "disassembly": "",
                    "pseudocode": "",
                    "note": f"Failed to process caller: {e}"
                })
                caller_count += 1
        
        return context
    
    def format_context_for_ai(self, context: Dict[str, Any]) -> str:
        """Format gathered context for AI analysis"""
        if "error" in context:
            return f"Error: {context['error']}"
        
        formatted = f"""=== FUNCTION ANALYSIS CONTEXT ===

Target Function: {context['function_name']} ({context['function_address']})
Function Size: {context['function_size']} bytes

=== DISASSEMBLY ===
{context['disassembly']}

=== PSEUDOCODE ===
{context['pseudocode']}

=== CALLS MADE BY THIS FUNCTION ===
"""
        
        if not context['calls_made']:
            formatted += "This function makes no external calls.\n"
        else:
            formatted += f"This function calls {len(context['calls_made'])} external functions:\n"
            for i, call in enumerate(context['calls_made'], 1):
                formatted += f"""
--- Called Function {i}: {call['target_name']} ({call['target_address']}) at {call['call_site']} [{call['xref_type']}] ---
"""
                if "note" in call:
                    formatted += f"Note: {call['note']}\n"
                
                # Add detailed analysis of called function
                disassembly = call.get('disassembly', '')
                if disassembly:
                    formatted += f"Disassembly:\n{disassembly}\n\n"
                
                pseudocode = call.get('pseudocode', '')
                if pseudocode:
                    formatted += f"Pseudocode:\n{pseudocode}\n"
        
        formatted += "\n=== CALLERS AND USAGE CONTEXT ===\n"
        
        if not context['callers']:
            formatted += "No callers found - this may be a dead function or entry point.\n"
        else:
            for i, caller in enumerate(context['callers'], 1):
                formatted += f"""
--- Caller {i}: {caller.get('name', 'Unknown')} ({caller.get('address', 'N/A')}) [{caller.get('xref_type', 'Unknown')}] ---
"""
                if "note" in caller:
                    formatted += f"Note: {caller['note']}\n"
                
                # Safely access disassembly
                disassembly = caller.get('disassembly', '')
                if disassembly:
                    formatted += f"Disassembly:\n{disassembly}\n\n"
                
                # Safely access pseudocode
                pseudocode = caller.get('pseudocode', '')
                if pseudocode:
                    formatted += f"Pseudocode:\n{pseudocode}\n"
        
        return formatted
    
    def estimate_context_size(self, context: Dict[str, Any]) -> int:
        """Estimate the token count of the formatted context"""
        if "error" in context:
            return 0
        
        # Get the formatted context
        formatted_context = self.format_context_for_ai(context)
        char_count = len(formatted_context)
        
        # Account for system prompt (approximately 300 tokens)
        system_prompt_tokens = 300
        
        # Account for user prompt structure and formatting (approximately 200 tokens)
        prompt_structure_tokens = 200
        
        # More accurate token estimation: 
        # - Technical content with code averages about 3.5 characters per token
        # - Add overhead for system prompt and formatting
        content_tokens = char_count // 3.5
        estimated_tokens = int(content_tokens + system_prompt_tokens + prompt_structure_tokens)
        
        print(f"AutoReverse: Context size estimate: {char_count} chars ≈ {estimated_tokens} tokens (improved estimation)")
        return estimated_tokens 
    
    def should_truncate_context(self, context: Dict[str, Any], max_tokens: int = 200000) -> bool:
        """Check if context should be truncated to avoid API limits"""
        estimated_size = self.estimate_context_size(context)
        return estimated_size > max_tokens 

    def gather_data_context(self, ea: int, max_xref_lines: int = 50, max_xrefs: int = 10) -> Dict[str, Any]:
        """Gather comprehensive context for data elements with detailed XREF analysis"""
        try:
            # Get basic data info with improved naming
            name = self.get_improved_data_name(ea)
            
            context = {
                "data_name": name,
                "data_address": f"0x{ea:X}",
                "data_type": "",
                "data_value": "",
                "data_size": 0,
                "xrefs_to": [],
                "xrefs_from": [],
                "surrounding_data": ""
            }
            
            # Get data type and size
            try:
                # Get item size first
                item_size = ida_bytes.get_item_size(ea)
                context["data_size"] = item_size
                
                # Get data type information from IDA's type system
                try:
                    import ida_typeinf
                    tinfo = ida_typeinf.tinfo_t()
                    if ida_typeinf.get_tinfo(tinfo, ea):
                        context["data_type"] = str(tinfo)
                    else:
                        # Fallback: determine type from size and flags
                        flags = ida_bytes.get_flags(ea)
                        if ida_bytes.is_data(flags):
                            if item_size == 1:
                                context["data_type"] = "byte"
                            elif item_size == 2:
                                context["data_type"] = "word"
                            elif item_size == 4:
                                context["data_type"] = "dword"
                            elif item_size == 8:
                                context["data_type"] = "qword"
                            else:
                                context["data_type"] = f"data[{item_size}]"
                        else:
                            context["data_type"] = "unknown"
                except:
                    # Simple fallback based on size
                    if item_size == 1:
                        context["data_type"] = "byte"
                    elif item_size == 2:
                        context["data_type"] = "word"
                    elif item_size == 4:
                        context["data_type"] = "dword"
                    elif item_size == 8:
                        context["data_type"] = "qword"
                    else:
                        context["data_type"] = f"data[{item_size}]"
                
                # Get value based on size
                if item_size == 1:
                    val = ida_bytes.get_byte(ea)
                    context["data_value"] = f"0x{val:02X} ({val})"
                elif item_size == 2:
                    val = ida_bytes.get_word(ea)
                    context["data_value"] = f"0x{val:04X} ({val})"
                elif item_size == 4:
                    val = ida_bytes.get_dword(ea)
                    context["data_value"] = f"0x{val:08X} ({val})"
                elif item_size == 8:
                    val = ida_bytes.get_qword(ea)
                    context["data_value"] = f"0x{val:016X} ({val})"
                else:
                    # Default to dword for unknown sizes
                    val = ida_bytes.get_dword(ea)
                    context["data_value"] = f"0x{val:08X} ({val}) [as dword]"
                    
            except Exception as e:
                context["data_value"] = f"Error reading value: {e}"
                context["data_size"] = 0
                context["data_type"] = "error"
            
            # Gather comprehensive XREF TO analysis (who references this data)
            xrefs_to = []
            try:
                # Get data references
                xref = ida_xref.get_first_dref_to(ea)
                while xref != idaapi.BADADDR:
                    xrefs_to.append(xref)
                    xref = ida_xref.get_next_dref_to(ea, xref)
                
                # Get code references
                xref = ida_xref.get_first_cref_to(ea)
                while xref != idaapi.BADADDR:
                    xrefs_to.append(xref)
                    xref = ida_xref.get_next_cref_to(ea, xref)
                    
            except Exception as e:
                print(f"Error getting XREFs TO for {name}: {e}")
            
            # Process XREFs TO with detailed analysis
            analyzed_funcs = set()
            xref_count = 0
            
            for xref_addr in sorted(xrefs_to):
                if xref_count >= max_xrefs:
                    remaining = len(xrefs_to) - xref_count
                    context["xrefs_to"].append({
                        "function_name": f"... and {remaining} more references",
                        "reference_address": "N/A",
                        "instruction": "Truncated for API limits",
                        "disassembly": "",
                        "pseudocode": "",
                        "note": f"Context truncated. {remaining} additional references not shown."
                    })
                    break
                
                try:
                    # Get the function containing this reference
                    ref_func = ida_funcs.get_func(xref_addr)
                    if ref_func:
                        func_name = ida_funcs.get_func_name(ref_func.start_ea)
                        
                        xref_info = {
                            "function_name": func_name,
                            "reference_address": f"0x{xref_addr:X}",
                            "instruction": "",
                            "disassembly": "",
                            "pseudocode": "",
                            "function_start": f"0x{ref_func.start_ea:X}"
                        }
                        
                        # Get instruction at reference point
                        try:
                            disasm = idc.generate_disasm_line(xref_addr, 0)
                            if disasm:
                                xref_info["instruction"] = disasm
                        except Exception as e:
                            xref_info["instruction"] = f"<disassembly error: {e}>"
                        
                        # Get comprehensive function context (if not already analyzed)
                        if ref_func.start_ea not in analyzed_funcs:
                            try:
                                # Get disassembly with highlighted reference
                                xref_info["disassembly"] = self.get_disassembly_lines(
                                    ref_func.start_ea, max_xref_lines, xref_addr, True)
                            except Exception as e:
                                xref_info["disassembly"] = f"Disassembly error: {e}"
                            
                            try:
                                xref_info["pseudocode"] = self.get_pseudocode_str(ref_func.start_ea)
                            except Exception as e:
                                xref_info["pseudocode"] = f"Pseudocode error: {e}"
                            
                            analyzed_funcs.add(ref_func.start_ea)
                        else:
                            xref_info["note"] = "Function already analyzed above"
                        
                        context["xrefs_to"].append(xref_info)
                    else:
                        # Reference not in function
                        xref_info = {
                            "function_name": f"<not in function>",
                            "reference_address": f"0x{xref_addr:X}",
                            "instruction": "",
                            "disassembly": "",
                            "pseudocode": "",
                            "note": "Reference outside of any function"
                        }
                        
                        try:
                            disasm = idc.generate_disasm_line(xref_addr, 0)
                            if disasm:
                                xref_info["instruction"] = disasm
                        except Exception as e:
                            xref_info["instruction"] = f"<disassembly error: {e}>"
                        
                        context["xrefs_to"].append(xref_info)
                    
                    xref_count += 1
                    
                except Exception as e:
                    print(f"Error processing XREF at {xref_addr:X}: {e}")
                    context["xrefs_to"].append({
                        "function_name": f"<error: {e}>",
                        "reference_address": f"0x{xref_addr:X}",
                        "instruction": "Error processing reference",
                        "disassembly": "",
                        "pseudocode": "",
                        "note": f"Failed to process reference: {e}"
                    })
                    xref_count += 1
            
            # Analyze if this data points to something (XREFS FROM) - Enhanced for WoW
            try:
                dword_val = ida_bytes.get_dword(ea)
                
                # Check for special WoW values first
                if dword_val == 0xFFFFFFFF:
                    context["xrefs_from"].append({
                        "note": "Data contains 0xFFFFFFFF - likely an uninitialized/invalid pointer marker (common in WoW for unused list heads, session IDs, etc.)"
                    })
                elif dword_val == 0x00000000:
                    context["xrefs_from"].append({
                        "note": "Data contains NULL (0x00000000) - explicitly set to empty/inactive state"
                    })
                elif 0x400000 < dword_val < 0x80000000:  # Reasonable address range
                    pointed_name = ida_name.get_name(dword_val)
                    if pointed_name:
                        context["xrefs_from"].append({
                            "target_name": pointed_name,
                            "target_address": f"0x{dword_val:X}",
                            "note": "This data appears to be a pointer"
                        })
                        
                        # If it points to a function, get some analysis
                        pointed_func = ida_funcs.get_func(dword_val)
                        if pointed_func:
                            try:
                                func_context = self.gather_function_context(dword_val, 30, 20, 3)
                                context["xrefs_from"][0]["function_analysis"] = func_context
                            except Exception as e:
                                context["xrefs_from"][0]["note"] += f" (Function analysis error: {e})"
                    else:
                        context["xrefs_from"].append({
                            "note": f"Data contains address 0x{dword_val:X} but no symbol found at that location"
                        })
                else:
                    # Check if it might be a data value rather than pointer
                    if dword_val <= 0xFFFF:
                        context["xrefs_from"].append({
                            "note": f"Data contains small value 0x{dword_val:X} ({dword_val}) - likely a counter, ID, or flag rather than pointer"
                        })
                    else:
                        context["xrefs_from"].append({
                            "note": f"Data contains 0x{dword_val:X} - outside typical pointer range, likely a large value or encoded data"
                        })
            except Exception as e:
                context["xrefs_from"].append({
                    "note": f"Error analyzing pointer: {e}"
                })
            
            # Get surrounding data context
            try:
                surrounding = []
                start_addr = ea - 32
                end_addr = ea + 32
                
                for addr in range(start_addr, end_addr, 4):
                    if addr < 0:
                        continue
                    try:
                        val = ida_bytes.get_dword(addr)
                        addr_name = self.get_improved_data_name(addr)
                        
                        # Get type information for this address
                        addr_type = ""
                        try:
                            import ida_typeinf
                            tinfo = ida_typeinf.tinfo_t()
                            if ida_typeinf.get_tinfo(tinfo, addr):
                                addr_type = str(tinfo)
                            else:
                                # Fallback: get type from flags and size
                                flags = ida_bytes.get_flags(addr)
                                if ida_bytes.is_data(flags):
                                    item_size = ida_bytes.get_item_size(addr)
                                    if item_size == 1:
                                        addr_type = "byte"
                                    elif item_size == 2:
                                        addr_type = "word" 
                                    elif item_size == 4:
                                        addr_type = "dword"
                                    elif item_size == 8:
                                        addr_type = "qword"
                                    else:
                                        addr_type = f"data[{item_size}]"
                                elif ida_bytes.is_code(flags):
                                    addr_type = "code"
                                else:
                                    addr_type = "unknown"
                        except:
                            addr_type = "dword"  # Default fallback
                        
                        entry = {
                            "address": f"0x{addr:08X}",
                            "value": f"0x{val:08X}",
                            "name": addr_name,
                            "type": addr_type,
                            "is_target": addr == ea
                        }
                        surrounding.append(entry)
                    except Exception as e:
                        # Add error entry for debugging
                        entry = {
                            "address": f"0x{addr:08X}",
                            "value": f"<error: {e}>",
                            "name": None,
                            "type": "error",
                            "is_target": addr == ea
                        }
                        surrounding.append(entry)
                
                context["surrounding_data"] = surrounding
                
            except Exception as e:
                context["surrounding_data"] = f"Error getting surrounding data: {e}"
            
            return context
            
        except Exception as e:
            return {"error": f"Failed to gather data context: {e}"}

    def format_data_context_for_ai(self, context: Dict[str, Any]) -> str:
        """Format gathered data context for AI analysis"""
        if "error" in context:
            return f"Error: {context['error']}"
        
        formatted = f"""=== DATA ANALYSIS CONTEXT ===

Target Data: {context['data_name']} ({context['data_address']})
Data Type: {context.get('data_type', 'Unknown')}
Data Size: {context.get('data_size', 0)} bytes
Current Value: {context.get('data_value', 'Unknown')}

=== REFERENCES TO THIS DATA ===
"""
        
        if not context['xrefs_to']:
            formatted += "No references found - this data may be unused.\n"
        else:
            formatted += f"This data is referenced by {len(context['xrefs_to'])} locations:\n"
            for i, xref in enumerate(context['xrefs_to'], 1):
                formatted += f"""
--- Reference {i}: {xref.get('function_name', 'Unknown')} at {xref.get('reference_address', 'N/A')} ---
Instruction: {xref.get('instruction', 'Unknown')}
"""
                if "note" in xref:
                    formatted += f"Note: {xref['note']}\n"
                
                # Add detailed function analysis
                disassembly = xref.get('disassembly', '')
                if disassembly and "already analyzed" not in xref.get('note', ''):
                    formatted += f"Function Disassembly:\n{disassembly}\n\n"
                
                pseudocode = xref.get('pseudocode', '')
                if pseudocode and "already analyzed" not in xref.get('note', ''):
                    formatted += f"Function Pseudocode:\n{pseudocode}\n"
        
        formatted += "\n=== REFERENCES FROM THIS DATA ===\n"
        
        if not context['xrefs_from']:
            formatted += "This data does not appear to point to anything.\n"
        else:
            for xref_from in context['xrefs_from']:
                if "target_name" in xref_from:
                    formatted += f"Points to: {xref_from['target_name']} ({xref_from['target_address']})\n"
                    if "function_analysis" in xref_from:
                        fa = xref_from['function_analysis']
                        formatted += f"Pointed Function Analysis:\n"
                        formatted += f"Function: {fa.get('function_name', 'Unknown')}\n"
                        formatted += f"Disassembly:\n{fa.get('disassembly', 'N/A')}\n"
                        formatted += f"Pseudocode:\n{fa.get('pseudocode', 'N/A')}\n"
                formatted += f"Note: {xref_from.get('note', '')}\n"
        
        formatted += "\n=== SURROUNDING DATA CONTEXT ===\n"
        
        if isinstance(context['surrounding_data'], list):
            for entry in context['surrounding_data']:
                marker = " >>> " if entry['is_target'] else "     "
                name_part = f" ({entry['name']})" if entry['name'] else ""
                type_part = f" [{entry['type']}]" if entry.get('type') and entry['type'] != "dword" else ""
                formatted += f"{marker}{entry['address']}: {entry['value']}{name_part}{type_part}\n"
        else:
            formatted += f"{context['surrounding_data']}\n"
        
        return formatted 

    def get_improved_data_name(self, ea: int) -> str:
        """Get improved name for data elements, providing more context for unnamed variables"""
        # Try to get the actual name first
        name = ida_name.get_name(ea)
        if name and not name.startswith(('dword_', 'byte_', 'word_', 'qword_', 'unk_')):
            return name
        
        # For auto-generated names, try to provide more context
        if name and name.startswith('dword_'):
            # Check if this is in a known data section that might indicate purpose
            segment = ida_segment.getseg(ea)
            if segment:
                seg_name = ida_segment.get_segm_name(segment)
                if seg_name:
                    if '.data' in seg_name or 'data' in seg_name:
                        return f"{name} (global data)"
                    elif '.bss' in seg_name or 'bss' in seg_name:
                        return f"{name} (uninitialized data)"
                    elif '.rdata' in seg_name:
                        return f"{name} (read-only data)"
        
        # Return the name as-is, or generate a fallback
        return name or f"data_{ea:X}" 