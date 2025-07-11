"""
Structure Analyzer for AutoReverse Plugin
Analyzes and creates structures in IDA Pro 9.0
"""

import ida_bytes
import ida_typeinf
import ida_kernwin
import ida_name
import ida_segment
import ida_funcs
import ida_ua
import ida_idaapi
import ida_nalt
from typing import Optional, List, Dict, Any

class StructAnalyzer:
    def __init__(self):
        self.gemini_client = None
    
    def set_gemini_client(self, client):
        """Set the Gemini client for AI analysis"""
        self.gemini_client = client
    
    def analyze_at_address(self, ea: int) -> Optional[str]:
        """Analyze structure at the given address"""
        try:
            # Get data at address
            data_info = self.get_data_info(ea)
            if not data_info:
                return "No analyzable data found at this address"
            
            # Create structure if it doesn't exist
            struct_name = f"struct_{ea:X}"
            if self.create_structure_from_data(struct_name, data_info):
                result = f"Created structure {struct_name} at address 0x{ea:X}\n\n"
                result += f"Structure layout:\n{self.format_structure_info(data_info)}"
                
                # Add AI analysis if available
                if self.gemini_client:
                    ai_analysis = self.gemini_client.analyze_structure(
                        self.format_structure_info(data_info)
                    )
                    if ai_analysis:
                        result += f"\n\nAI Analysis:\n{ai_analysis}"
                
                return result
            else:
                return "Failed to create structure"
                
        except Exception as e:
            print(f"Error analyzing structure: {e}")
            return f"Error analyzing structure: {e}"
    
    def get_data_info(self, ea: int) -> Optional[Dict[str, Any]]:
        """Get information about data at address"""
        try:
            # Check if address is valid
            if not ida_bytes.is_loaded(ea):
                return None
            
            # Get segment info
            seg = ida_segment.getseg(ea)
            if not seg:
                return None
            
            # Analyze data pattern
            data_info = {
                'address': ea,
                'size': 0,
                'fields': [],
                'patterns': []
            }
            
            # Try to determine structure size and fields
            current_ea = ea
            field_offset = 0
            
            # Read up to 256 bytes or until we hit different data
            max_size = min(256, seg.end_ea - ea)
            
            for i in range(0, max_size, 4):  # Analyze in 4-byte chunks
                if current_ea + 4 > seg.end_ea:
                    break
                
                # Get the data
                dword_val = ida_bytes.get_dword(current_ea)
                
                # Determine field type based on value
                field_type = self.guess_field_type(dword_val, current_ea)
                
                field_info = {
                    'offset': field_offset,
                    'size': 4,
                    'type': field_type,
                    'value': dword_val,
                    'address': current_ea
                }
                
                data_info['fields'].append(field_info)
                
                current_ea += 4
                field_offset += 4
                
                # Stop if we've analyzed enough or hit a clear boundary
                if len(data_info['fields']) >= 16:
                    break
            
            data_info['size'] = field_offset
            return data_info
            
        except Exception as e:
            print(f"Error getting data info: {e}")
            return None
    
    def guess_field_type(self, value: int, ea: int) -> str:
        """Guess the type of a field based on its value"""
        try:
            # Check if it's a pointer
            if self.is_likely_pointer(value):
                return "void*"
            
            # Check if it's a small integer (likely enum/flag)
            if 0 <= value <= 0xFFFF:
                return "int"
            
            # Check if it's a large integer
            if value > 0xFFFF:
                return "DWORD"
            
            # Default to DWORD
            return "DWORD"
            
        except:
            return "DWORD"
    
    def is_likely_pointer(self, value: int) -> bool:
        """Check if a value is likely a pointer"""
        try:
            # Check if the value points to a valid address
            if ida_bytes.is_loaded(value):
                return True
            
            # Check if it's in a reasonable pointer range
            if 0x400000 <= value <= 0x7FFFFFFF:  # Common Windows address ranges
                return True
            
            return False
            
        except:
            return False
    
    def create_structure_from_data(self, struct_name: str, data_info: Dict[str, Any]) -> bool:
        """Create a structure from analyzed data"""
        try:
            # Create a new UDT (User Defined Type)
            udt_data = ida_typeinf.udt_type_data_t()
            udt_data.is_union = False  # Create a struct, not union
            
            # Add fields to the structure
            for field in data_info['fields']:
                # Create member
                member = ida_typeinf.udt_member_t()
                member.name = f"field_{field['offset']:X}"
                member.type = self.get_ida_type(field['type'])
                member.offset = field['offset']
                member.size = field['size']
                
                # Add member to UDT
                udt_data.push_back(member)
            
            # Create the type info
            tinfo = ida_typeinf.tinfo_t()
            if not tinfo.create_udt(udt_data, ida_typeinf.BTF_STRUCT):
                print("Failed to create UDT")
                return False
            
            # Set the structure name in the type library
            if not ida_typeinf.set_named_type(None, struct_name, tinfo, 0):
                print("Failed to set named type")
                return False
            
            print(f"Successfully created structure {struct_name}")
            return True
            
        except Exception as e:
            print(f"Error creating structure: {e}")
            return False
    
    def get_ida_type(self, type_str: str) -> ida_typeinf.tinfo_t:
        """Convert string type to IDA tinfo_t"""
        try:
            tinfo = ida_typeinf.tinfo_t()
            
            if type_str == "void*":
                # Create pointer type
                ptr_tinfo = ida_typeinf.tinfo_t()
                ptr_tinfo.create_ptr(ida_typeinf.tinfo_t())
                return ptr_tinfo
            elif type_str == "int":
                if not tinfo.get_named_type(None, "int"):
                    # Fallback to creating basic int type
                    tinfo.create_simple_type(ida_typeinf.BT_INT)
                return tinfo
            elif type_str == "DWORD":
                if not tinfo.get_named_type(None, "DWORD"):
                    # Fallback to creating basic DWORD type
                    tinfo.create_simple_type(ida_typeinf.BT_INT | ida_typeinf.BTMT_UNSIGNED)
                return tinfo
            else:
                # Default to DWORD
                tinfo.create_simple_type(ida_typeinf.BT_INT | ida_typeinf.BTMT_UNSIGNED)
                return tinfo
                
        except Exception as e:
            print(f"Error getting IDA type: {e}")
            # Return a basic int type as fallback
            fallback = ida_typeinf.tinfo_t()
            fallback.create_simple_type(ida_typeinf.BT_INT)
            return fallback
    
    def format_structure_info(self, data_info: Dict[str, Any]) -> str:
        """Format structure information for display"""
        result = f"Structure at 0x{data_info['address']:X} (size: {data_info['size']} bytes)\n"
        result += "-" * 50 + "\n"
        
        for field in data_info['fields']:
            result += f"  +0x{field['offset']:02X}: {field['type']:<8} field_{field['offset']:X} = 0x{field['value']:X}\n"
        
        return result 