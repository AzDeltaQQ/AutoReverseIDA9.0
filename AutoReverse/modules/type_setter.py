"""
Type Setter for AutoReverse Plugin
Sets types for functions and variables in IDA Pro 9.0
"""

import ida_typeinf
import ida_funcs
import ida_kernwin
import ida_name
import ida_bytes
import ida_hexrays
import re
from typing import Optional, List, Dict, Any

class TypeSetter:
    def __init__(self):
        self.gemini_client = None
    
    def set_gemini_client(self, client):
        """Set the Gemini client for AI analysis"""
        self.gemini_client = client
    
    def set_function_type(self, func_ea: int) -> bool:
        """Set function type based on analysis"""
        try:
            func = ida_funcs.get_func(func_ea)
            if not func:
                return False
            
            func_name = ida_funcs.get_func_name(func_ea)
            
            # Get decompiled code if available
            code = self.get_decompiled_code(func_ea)
            if not code:
                return False
            
            # Get AI suggestion for function signature
            if self.gemini_client:
                suggestion = self.gemini_client.suggest_function_signature(func_name, code)
                if suggestion:
                    # Parse the suggestion and apply it
                    return self.apply_function_signature(func_ea, suggestion)
            
            # Fallback to basic analysis
            return self.analyze_and_set_basic_type(func_ea, code)
            
        except Exception as e:
            print(f"Error setting function type: {e}")
            return False
    
    def get_decompiled_code(self, func_ea: int) -> Optional[str]:
        """Get decompiled code for function"""
        try:
            if not ida_hexrays.init_hexrays_plugin():
                return None
            
            cfunc = ida_hexrays.decompile(func_ea)
            if cfunc:
                return str(cfunc)
            
            return None
            
        except Exception as e:
            print(f"Error getting decompiled code: {e}")
            return None
    
    def apply_function_signature(self, func_ea: int, signature: str) -> bool:
        """Apply function signature from AI suggestion"""
        try:
            # Extract function signature using regex
            # Look for patterns like: int function_name(int param1, char* param2)
            signature_pattern = r'(\w+(?:\s*\*)?)\s+(\w+)\s*\(([^)]*)\)'
            match = re.search(signature_pattern, signature)
            
            if not match:
                print("Could not parse function signature")
                return False
            
            return_type = match.group(1).strip()
            func_name = match.group(2).strip()
            params = match.group(3).strip()
            
            # Create function type
            func_type = self.create_function_type(return_type, params)
            if not func_type:
                return False
            
            # Apply the type
            if ida_typeinf.apply_type(func_ea, func_type):
                print(f"Applied function type: {signature}")
                return True
            else:
                print("Failed to apply function type")
                return False
                
        except Exception as e:
            print(f"Error applying function signature: {e}")
            return False
    
    def create_function_type(self, return_type: str, params: str) -> Optional[ida_typeinf.tinfo_t]:
        """Create function type from strings"""
        try:
            # Create function type info
            func_tinfo = ida_typeinf.tinfo_t()
            
            # Create return type
            ret_tinfo = self.parse_type_string(return_type)
            if not ret_tinfo:
                return None
            
            # Parse parameters
            param_types = []
            if params and params.strip() != "void":
                param_list = [p.strip() for p in params.split(',')]
                for param in param_list:
                    if param:
                        # Split type and name (e.g., "int param1" -> "int")
                        parts = param.split()
                        if len(parts) >= 1:
                            param_type = parts[0]
                            param_tinfo = self.parse_type_string(param_type)
                            if param_tinfo:
                                param_types.append(param_tinfo)
            
            # Create function type
            func_details = ida_typeinf.func_type_data_t()
            func_details.rettype = ret_tinfo
            
            # Add parameters
            for param_type in param_types:
                param_info = ida_typeinf.funcarg_t()
                param_info.type = param_type
                func_details.push_back(param_info)
            
            # Create the function type
            if func_tinfo.create_func(func_details):
                return func_tinfo
            
            return None
            
        except Exception as e:
            print(f"Error creating function type: {e}")
            return None
    
    def parse_type_string(self, type_str: str) -> Optional[ida_typeinf.tinfo_t]:
        """Parse a type string into tinfo_t"""
        try:
            tinfo = ida_typeinf.tinfo_t()
            
            # Handle pointer types
            if type_str.endswith('*'):
                base_type = type_str[:-1].strip()
                base_tinfo = self.parse_type_string(base_type)
                if base_tinfo:
                    tinfo.create_ptr(base_tinfo)
                    return tinfo
            
            # Handle basic types
            type_map = {
                'void': ida_typeinf.BT_VOID,
                'int': ida_typeinf.BT_INT,
                'char': ida_typeinf.BT_INT8,
                'short': ida_typeinf.BT_INT16,
                'long': ida_typeinf.BT_INT32,
                'DWORD': ida_typeinf.BT_INT32 | ida_typeinf.BTMT_UNSIGNED,
                'WORD': ida_typeinf.BT_INT16 | ida_typeinf.BTMT_UNSIGNED,
                'BYTE': ida_typeinf.BT_INT8 | ida_typeinf.BTMT_UNSIGNED,
                'float': ida_typeinf.BT_FLOAT,
                'double': ida_typeinf.BT_DOUBLE,
            }
            
            if type_str in type_map:
                tinfo.create_simple_type(type_map[type_str])
                return tinfo
            
            # Try to get named type
            if tinfo.get_named_type(None, type_str):
                return tinfo
            
            # Default to int
            tinfo.create_simple_type(ida_typeinf.BT_INT)
            return tinfo
            
        except Exception as e:
            print(f"Error parsing type string: {e}")
            return None
    
    def analyze_and_set_basic_type(self, func_ea: int, code: str) -> bool:
        """Analyze function and set basic type without AI"""
        try:
            # Basic heuristics for function type
            return_type = "int"  # Default
            
            # Look for return statements
            if "return" in code:
                if "return 0" in code or "return -1" in code:
                    return_type = "int"
                elif "return NULL" in code or "return 0LL" in code:
                    return_type = "void*"
            
            # Create simple function type
            func_tinfo = ida_typeinf.tinfo_t()
            ret_tinfo = self.parse_type_string(return_type)
            
            if ret_tinfo:
                func_details = ida_typeinf.func_type_data_t()
                func_details.rettype = ret_tinfo
                
                if func_tinfo.create_func(func_details):
                    if ida_typeinf.apply_type(func_ea, func_tinfo):
                        print(f"Applied basic function type: {return_type}")
                        return True
            
            return False
            
        except Exception as e:
            print(f"Error setting basic type: {e}")
            return False 