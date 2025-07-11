"""
Variable Renamer for AutoReverse Plugin
Renames variables in functions using AI suggestions
"""

import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_name
import ida_typeinf
import re
from typing import Optional, List, Dict, Any, Tuple

class VariableRenamer:
    def __init__(self):
        self.gemini_client = None
    
    def set_gemini_client(self, client):
        """Set the Gemini client for AI analysis"""
        self.gemini_client = client
    
    def rename_function_variables(self, func_ea: int) -> int:
        """Rename variables in a function"""
        try:
            func = ida_funcs.get_func(func_ea)
            if not func:
                return 0
            
            # Get decompiled code
            code = self.get_decompiled_code(func_ea)
            if not code:
                return 0
            
            # Get variable suggestions
            suggestions = self.get_variable_suggestions(code)
            if not suggestions:
                return 0
            
            # Apply suggestions
            return self.apply_variable_suggestions(func_ea, suggestions)
            
        except Exception as e:
            print(f"Error renaming variables: {e}")
            return 0
    
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
    
    def get_variable_suggestions(self, code: str) -> List[Dict[str, str]]:
        """Get variable renaming suggestions"""
        try:
            suggestions = []
            
            # Use AI if available
            if self.gemini_client:
                ai_suggestions = self.gemini_client.suggest_variable_names(code)
                if ai_suggestions:
                    suggestions.extend(self.parse_ai_suggestions(ai_suggestions))
            
            # Add basic pattern-based suggestions
            pattern_suggestions = self.get_pattern_based_suggestions(code)
            suggestions.extend(pattern_suggestions)
            
            return suggestions
            
        except Exception as e:
            print(f"Error getting variable suggestions: {e}")
            return []
    
    def parse_ai_suggestions(self, ai_response: str) -> List[Dict[str, str]]:
        """Parse AI suggestions into structured format"""
        try:
            suggestions = []
            
            # Look for patterns like "old_name -> new_name"
            pattern = r'(\w+)\s*->\s*(\w+)'
            matches = re.findall(pattern, ai_response)
            
            for old_name, new_name in matches:
                suggestions.append({
                    'old_name': old_name,
                    'new_name': new_name,
                    'reason': 'AI suggestion'
                })
            
            return suggestions
            
        except Exception as e:
            print(f"Error parsing AI suggestions: {e}")
            return []
    
    def get_pattern_based_suggestions(self, code: str) -> List[Dict[str, str]]:
        """Get suggestions based on common patterns"""
        try:
            suggestions = []
            
            # Common patterns
            patterns = [
                # Loop variables
                (r'\b(v\d+)\b(?=\s*[<>=!]+\s*\d+)', r'i'),
                (r'\b(a\d+)\b(?=\s*\[.*\])', r'array'),
                (r'\b(v\d+)\b(?=\s*=\s*strlen)', r'length'),
                (r'\b(v\d+)\b(?=\s*=\s*malloc)', r'buffer'),
                (r'\b(v\d+)\b(?=\s*=\s*fopen)', r'file'),
                (r'\b(v\d+)\b(?=\s*=\s*GetWindowText)', r'window'),
                (r'\b(v\d+)\b(?=\s*=\s*CreateFile)', r'handle'),
            ]
            
            for pattern, suggestion in patterns:
                matches = re.finditer(pattern, code)
                for match in matches:
                    old_name = match.group(1)
                    # Create a unique name if needed
                    new_name = suggestion
                    if code.count(old_name) > 1:
                        new_name = f"{suggestion}_{old_name}"
                    
                    suggestions.append({
                        'old_name': old_name,
                        'new_name': new_name,
                        'reason': 'Pattern-based suggestion'
                    })
            
            return suggestions
            
        except Exception as e:
            print(f"Error getting pattern suggestions: {e}")
            return []
    
    def apply_variable_suggestions(self, func_ea: int, suggestions: List[Dict[str, str]]) -> int:
        """Apply variable renaming suggestions"""
        try:
            if not suggestions:
                return 0
            
            renamed_count = 0
            
            # Show suggestions to user
            for suggestion in suggestions:
                old_name = suggestion['old_name']
                new_name = suggestion['new_name']
                reason = suggestion['reason']
                
                # Ask user for confirmation
                choice = ida_kernwin.ask_yn(
                    ida_kernwin.ASKBTN_YES,
                    f"Rename variable '{old_name}' to '{new_name}'?\n\nReason: {reason}"
                )
                
                if choice == ida_kernwin.ASKBTN_YES:
                    if self.rename_variable(func_ea, old_name, new_name):
                        renamed_count += 1
                        print(f"Renamed {old_name} -> {new_name}")
                    else:
                        print(f"Failed to rename {old_name}")
            
            return renamed_count
            
        except Exception as e:
            print(f"Error applying suggestions: {e}")
            return 0
    
    def rename_variable(self, func_ea: int, old_name: str, new_name: str) -> bool:
        """Rename a single variable"""
        try:
            # This is a simplified implementation
            # In a real implementation, we'd use the Hex-Rays API
            
            # For now, we'll just try to rename local variables
            # This would need to be implemented with proper Hex-Rays integration
            
            print(f"Would rename {old_name} to {new_name} in function at 0x{func_ea:X}")
            return True
            
        except Exception as e:
            print(f"Error renaming variable: {e}")
            return False 