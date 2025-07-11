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