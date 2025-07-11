"""
AutoReverse Plugin for IDA Pro 9.0
AI-powered reverse engineering assistant using Google Gemini
"""

import ida_idaapi
import ida_kernwin
import ida_hexrays
import ida_funcs
import ida_bytes
import ida_ua
import ida_segment
import ida_entry
import ida_typeinf
import ida_nalt
import ida_name
import ida_lines
import ida_pro
import sys
import os
import traceback
import json
import re
from pathlib import Path
import google.generativeai as genai
import threading
import ida_xref

# Add the AutoReverse modules directory to the Python path
plugin_dir = Path(__file__).parent
autoreverse_dir = plugin_dir / "AutoReverse"
modules_dir = autoreverse_dir / "modules"
if str(modules_dir) not in sys.path:
    sys.path.insert(0, str(modules_dir))

# Import our modules
try:
    from config_manager import ConfigManager
    from gemini_client import GeminiClient
    from struct_analyzer import StructAnalyzer
    from type_setter import TypeSetter
    from ui_manager import UIManager, ProgressDialog, AutoReverseResultsWidget
    from variable_renamer import VariableRenamer
    from context_gatherer import ContextGatherer
    
    MODULES_LOADED = True
    print("AutoReverse: All modules loaded successfully")
except ImportError as e:
    print(f"AutoReverse: Failed to import modules: {e}")
    print("AutoReverse: Running in fallback mode")
    MODULES_LOADED = False
    
    # Create dummy classes for fallback
    class DummyClass:
        def __init__(self, *args, **kwargs):
            pass
        def __getattr__(self, name):
            return lambda *args, **kwargs: None
    
    ConfigManager = DummyClass
    GeminiClient = DummyClass
    StructAnalyzer = DummyClass
    TypeSetter = DummyClass
    UIManager = DummyClass
    ProgressDialog = DummyClass
    AutoReverseResultsWidget = DummyClass
    VariableRenamer = DummyClass
    ContextGatherer = DummyClass

class ActionHandler(ida_kernwin.action_handler_t):
    """Action handler for menu callbacks"""
    def __init__(self, callback):
        ida_kernwin.action_handler_t.__init__(self)
        self.callback = callback
    
    def activate(self, ctx):
        try:
            self.callback()
            return 1
        except Exception as e:
            print(f"AutoReverse: Error in action handler: {e}")
            return 0
    
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class AutoReversePlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP
    comment = "AI-powered reverse engineering assistant using Google Gemini"
    help = "AutoReverse Plugin - AI-powered reverse engineering assistant"
    wanted_name = "AutoReverse"
    wanted_hotkey = ""

    def __init__(self):
        super().__init__()
        self.initialized = False
        self.config_manager = None
        self.gemini_client = None
        self.struct_analyzer = None
        self.type_setter = None
        self.ui_manager = None
        self.variable_renamer = None
        self.context_gatherer = None
        self.menu_items = []
        
        print("AutoReverse: Plugin initialized")

    def init(self):
        """Initialize the plugin"""
        try:
            print("AutoReverse: Initializing plugin components...")
            
            if not MODULES_LOADED:
                print("AutoReverse: Modules not loaded, creating fallback menu")
                self.create_fallback_menu()
                self.initialized = True
                return ida_idaapi.PLUGIN_KEEP
            
            # Initialize components
            self.config_manager = ConfigManager()
            self.gemini_client = GeminiClient()
            self.struct_analyzer = StructAnalyzer()
            self.type_setter = TypeSetter()
            self.ui_manager = UIManager()
            self.variable_renamer = VariableRenamer()
            self.context_gatherer = ContextGatherer()
            
            # Auto-load saved API key if available
            saved_api_key = self.config_manager.get_api_key()
            if saved_api_key:
                self.gemini_client.set_api_key(saved_api_key)
                print(f"AutoReverse: Loaded saved API key: {saved_api_key[:10]}...")
            else:
                print("AutoReverse: No saved API key found. Please configure your Gemini API key.")
            
            # Create menus
            self.create_menus()
            
            self.initialized = True
            print("AutoReverse: Plugin initialized successfully")
            return ida_idaapi.PLUGIN_KEEP
            
        except Exception as e:
            print(f"AutoReverse: Error during initialization: {e}")
            print(f"AutoReverse: Traceback: {traceback.format_exc()}")
            return ida_idaapi.PLUGIN_SKIP

    def create_fallback_menu(self):
        """Create a fallback menu when modules couldn't be loaded"""
        try:
            # Create action for fallback menu
            action_name = "AutoReverse:Fallback"
            action_desc = ida_kernwin.action_desc_t(
                action_name,
                "AutoReverse (Error)",
                ActionHandler(self.show_error_dialog),
                None,
                "AutoReverse plugin - module loading failed"
            )
            
            if ida_kernwin.register_action(action_desc):
                self.menu_items.append(action_name)
                if ida_kernwin.attach_action_to_menu("Edit/", action_name, ida_kernwin.SETMENU_APP):
                    print("AutoReverse: Created fallback menu")
                else:
                    print("AutoReverse: Failed to attach fallback menu")
            else:
                print("AutoReverse: Failed to register fallback action")
                
        except Exception as e:
            print(f"AutoReverse: Error creating fallback menu: {e}")

    def create_menus(self):
        """Create the plugin menus"""
        try:
            # Define menu actions
            menu_actions = [
                ("AutoReverse:ConfigureKey", "AutoReverse: Configure API Key", self.configure_api_key),
                ("AutoReverse:Settings", "AutoReverse: Settings", self.show_settings),
                ("AutoReverse:AnalyzeFunction", "AutoReverse: Analyze Current Item", self.analyze_function),
                ("AutoReverse:AnalyzeStructure", "AutoReverse: Analyze Structure", self.analyze_structure),
                ("AutoReverse:RenameVariables", "AutoReverse: Rename Variables", self.rename_variables),
                ("AutoReverse:SetFunctionType", "AutoReverse: Set Function Type", self.set_function_type),
                ("AutoReverse:About", "AutoReverse: About", self.show_about),
            ]
            
            # Register and attach actions
            for action_name, label, handler in menu_actions:
                action_desc = ida_kernwin.action_desc_t(
                    action_name,
                    label,
                    ActionHandler(handler),
                    None,
                    f"AutoReverse: {label.split(': ', 1)[1]}"
                )
                
                if ida_kernwin.register_action(action_desc):
                    self.menu_items.append(action_name)
                    if ida_kernwin.attach_action_to_menu("Edit/", action_name, ida_kernwin.SETMENU_APP):
                        print(f"AutoReverse: Created menu item: {label}")
                    else:
                        print(f"AutoReverse: Failed to attach menu item: {label}")
                else:
                    print(f"AutoReverse: Failed to register action: {action_name}")
                    
        except Exception as e:
            print(f"AutoReverse: Error creating menus: {e}")

    def show_error_dialog(self):
        """Show error dialog when modules couldn't be loaded"""
        ida_kernwin.info(
            "AutoReverse Plugin Error\n\n"
            "The plugin modules could not be loaded.\n"
            "Please check that all plugin files are in the correct location:\n"
            "plugins/AutoReverse/modules/\n\n"
            "Required files:\n"
            "- plugins/auto_reverse.py\n"
            "- plugins/AutoReverse/modules/__init__.py\n"
            "- plugins/AutoReverse/modules/config_manager.py\n"
            "- plugins/AutoReverse/modules/gemini_client.py\n"
            "- plugins/AutoReverse/modules/struct_analyzer.py\n"
            "- plugins/AutoReverse/modules/type_setter.py\n"
            "- plugins/AutoReverse/modules/ui_manager.py\n"
            "- plugins/AutoReverse/modules/variable_renamer.py"
        )

    def configure_api_key(self):
        """Configure the Gemini API key"""
        try:
            if not self.config_manager:
                ida_kernwin.warning("Config manager not available")
                return
                
            current_key = self.config_manager.get_api_key()
            if current_key:
                prompt = f"Current API key: {current_key[:10]}...\n\nEnter new API key (or leave empty to keep current):"
            else:
                prompt = "Enter your Google Gemini API key:"
            
            api_key = ida_kernwin.ask_str("", 0, prompt)
            if api_key:
                self.config_manager.set_api_key(api_key)
                self.gemini_client.set_api_key(api_key)
                ida_kernwin.info("API key configured successfully!")
            elif not current_key:
                ida_kernwin.warning("No API key configured")
                
        except Exception as e:
            print(f"AutoReverse: Error configuring API key: {e}")
            ida_kernwin.warning(f"Error configuring API key: {e}")

    def analyze_function(self):
        """Analyze the current function or data element with comprehensive context"""
        try:
            if not self.gemini_client or not self.context_gatherer:
                ida_kernwin.warning("Required components not available")
                return
                
            # Get current address
            ea = ida_kernwin.get_screen_ea()
            
            # Try to get function first
            func = ida_funcs.get_func(ea)
            if func:
                # It's a function - use existing function analysis
                self._analyze_function_at(func, ea)
            else:
                # It's not a function - analyze as data/offset/structure
                self._analyze_data_at(ea)
                
        except Exception as e:
            print(f"AutoReverse: Error analyzing item: {e}")
            print(f"AutoReverse: Error traceback: {traceback.format_exc()}")
            ida_kernwin.warning(f"Error analyzing item: {e}\n\nCheck IDA Output window for detailed error information.")

    def _analyze_function_at(self, func, ea):
        """Analyze a function at the given address"""
        # Get function name
        func_name = ida_funcs.get_func_name(func.start_ea)
        
        # Gather comprehensive context with limits for API efficiency
        print(f"AutoReverse: Gathering context for function {func_name}...")
        context_data = self.context_gatherer.gather_function_context(
            func.start_ea, 
            max_disasm_lines=80,    # Reduced from 100
            max_caller_lines=40,    # Reduced from 50
            max_callers=8          # Reduced from 10 for better API limits
        )
        
        if "error" in context_data:
            ida_kernwin.warning(f"Context gathering failed: {context_data['error']}")
            return
        
        # Check if context might be too large for API limits
        estimated_tokens = self.context_gatherer.estimate_context_size(context_data)
        if estimated_tokens > 200000:  # Conservative limit for free tier
            # Show warning and offer to continue
            choice = ida_kernwin.ask_yn(
                ida_kernwin.ASKBTN_YES,
                f"⚠️ Large Function Context Warning\n\n"
                f"Function: {func_name}\n"
                f"Estimated tokens: {estimated_tokens:,}\n"
                f"Free tier limit: 250,000 tokens/minute\n\n"
                f"This function has many cross-references and may exceed API limits.\n\n"
                f"Continue anyway? (May result in rate limiting error)"
            )
            if choice != ida_kernwin.ASKBTN_YES:
                return
        
        # Format context for AI analysis
        formatted_context = self.context_gatherer.format_context_for_ai(context_data)
        
        self._perform_analysis(f"Function Analysis: {func_name}", formatted_context, "function")

    def _analyze_data_at(self, ea):
        """Analyze data/offset/structure at the given address"""
        # Get name of the data element
        name = ida_name.get_name(ea)
        if not name:
            name = f"data_{ea:X}"
        
        print(f"AutoReverse: Gathering context for data element {name}...")
        
        # Gather data context
        data_context = self._gather_data_context(ea, name)
        
        self._perform_analysis(f"Data Analysis: {name}", data_context, "data")

    def _gather_data_context(self, ea, name):
        """Gather context for data elements"""
        context = f"=== DATA ANALYSIS FOR {name} ===\n\n"
        
        # Basic info
        context += f"**Address**: 0x{ea:X}\n"
        context += f"**Name**: {name}\n"
        
        # Get data type and size
        try:
            data_type = ida_bytes.get_type(ea)
            if data_type:
                context += f"**Type**: {data_type}\n"
        except:
            pass
        
        # Get the actual data/value
        try:
            # Try to get as different data types
            byte_val = ida_bytes.get_byte(ea)
            word_val = ida_bytes.get_word(ea)
            dword_val = ida_bytes.get_dword(ea)
            qword_val = ida_bytes.get_qword(ea)
            
            context += f"**Values**:\n"
            context += f"  - Byte: 0x{byte_val:02X} ({byte_val})\n"
            context += f"  - Word: 0x{word_val:04X} ({word_val})\n"
            context += f"  - DWord: 0x{dword_val:08X} ({dword_val})\n"
            context += f"  - QWord: 0x{qword_val:016X} ({qword_val})\n"
            
            # If it looks like a pointer, dereference it
            if dword_val > 0x400000 and dword_val < 0x80000000:  # Reasonable address range
                try:
                    pointed_name = ida_name.get_name(dword_val)
                    if pointed_name:
                        context += f"  - Points to: {pointed_name} (0x{dword_val:08X})\n"
                    else:
                        # Try to get some data from the pointed location
                        pointed_data = ida_bytes.get_bytes(dword_val, 16)
                        if pointed_data:
                            context += f"  - Points to data: {pointed_data.hex()}\n"
                except:
                    pass
            
        except Exception as e:
            context += f"**Error reading data**: {e}\n"
        
        # Get cross-references TO this data
        context += f"\n**=== REFERENCES TO {name} ===**\n"
        xref_count = 0
        
        # Get data references
        xref = ida_xref.get_first_dref_to(ea)
        while xref != ida_idaapi.BADADDR and xref_count < 10:
            ref_name = ida_name.get_name(xref)
            if not ref_name:
                ref_name = f"sub_{xref:X}"
                
            # Get the function containing this reference
            ref_func = ida_funcs.get_func(xref)
            if ref_func:
                ref_func_name = ida_funcs.get_func_name(ref_func.start_ea)
                context += f"  - Referenced by {ref_func_name} at 0x{xref:X}\n"
                
                # Get some context around the reference
                try:
                    disasm = ida_lines.generate_disasm_line(xref, 0)
                    context += f"    Instruction: {disasm}\n"
                except:
                    pass
            else:
                context += f"  - Referenced at 0x{xref:X}\n"
            
            xref_count += 1
            xref = ida_xref.get_next_dref_to(ea, xref)
        
        # Also check code references
        xref = ida_xref.get_first_cref_to(ea)
        while xref != ida_idaapi.BADADDR and xref_count < 10:
            ref_name = ida_name.get_name(xref)
            if not ref_name:
                ref_name = f"sub_{xref:X}"
                
            # Get the function containing this reference
            ref_func = ida_funcs.get_func(xref)
            if ref_func:
                ref_func_name = ida_funcs.get_func_name(ref_func.start_ea)
                context += f"  - Code reference from {ref_func_name} at 0x{xref:X}\n"
                
                # Get some context around the reference
                try:
                    disasm = ida_lines.generate_disasm_line(xref, 0)
                    context += f"    Instruction: {disasm}\n"
                except:
                    pass
            else:
                context += f"  - Code reference at 0x{xref:X}\n"
            
            xref_count += 1
            xref = ida_xref.get_next_cref_to(ea, xref)
        
        if xref_count >= 10:
            context += f"... and more references\n"
        elif xref_count == 0:
            context += "  - No references found\n"
        
        # Get cross-references FROM this data (if it's a pointer)
        context += f"\n**=== REFERENCES FROM {name} ===**\n"
        try:
            pointed_addr = ida_bytes.get_dword(ea)
            if pointed_addr > 0x400000 and pointed_addr < 0x80000000:
                pointed_name = ida_name.get_name(pointed_addr)
                if pointed_name:
                    context += f"  - Points to: {pointed_name} (0x{pointed_addr:08X})\n"
                    
                    # If it points to a function, get some info
                    pointed_func = ida_funcs.get_func(pointed_addr)
                    if pointed_func:
                        pointed_func_name = ida_funcs.get_func_name(pointed_func.start_ea)
                        context += f"    Function: {pointed_func_name}\n"
                        
                        # Get function signature if available
                        try:
                            func_type = ida_typeinf.get_type(pointed_addr)
                            if func_type:
                                context += f"    Type: {func_type}\n"
                        except:
                            pass
                else:
                    context += f"  - Points to unnamed location: 0x{pointed_addr:08X}\n"
            else:
                context += f"  - Not a valid pointer\n"
        except:
            context += f"  - Error analyzing pointer\n"
        
        # Add some surrounding context
        context += f"\n**=== SURROUNDING DATA ===**\n"
        try:
            # Show some data before and after
            start_ea = ea - 32
            end_ea = ea + 32
            
            for addr in range(start_ea, end_ea, 4):
                if addr < 0:
                    continue
                    
                try:
                    val = ida_bytes.get_dword(addr)
                    addr_name = ida_name.get_name(addr)
                    
                    marker = " >>> " if addr == ea else "     "
                    name_part = f" ({addr_name})" if addr_name else ""
                    
                    context += f"{marker}0x{addr:08X}: 0x{val:08X}{name_part}\n"
                except:
                    pass
        except:
            pass
        
        return context

    def _perform_analysis(self, title, context, analysis_type):
        """Perform the actual AI analysis"""
        if analysis_type == "function":
            system_prompt = """You are an expert x86 reverse engineer specializing in World of Warcraft 3.3.5a (build 12340) binary analysis.

CRITICAL ANALYSIS GUIDELINES:
1. Focus on ACTUAL function behavior, not potential bugs unless clearly evident
2. Decompiler artifacts (like uninitialized variables v7, v8) are often NORMAL - don't flag them as bugs unless you're certain
3. __thiscall convention is standard for C++ member functions - ECX contains 'this' pointer
4. WoW uses many custom data structures for game objects, packets, arrays, etc.
5. Be precise about calling conventions, parameter purposes, and data flow
6. Only mention security issues if they're clearly exploitable, not theoretical

ANALYSIS FOCUS:
- What does this function accomplish in the WoW client?
- How do the parameters relate to WoW game mechanics?
- What WoW systems might this function be part of?
- How do callers use this function?
- What are the actual data types and structures involved?

AVOID:
- False positive bug reports
- Speculation about uninitialized variables without clear evidence
- Generic security warnings
- Theoretical vulnerabilities"""

            user_prompt = f"""Analyze this WoW 3.3.5a function with full context:

{context}

Provide a focused analysis covering:
1. **Function Purpose**: What does this function do in WoW's context?
2. **Parameters & Calling Convention**: Analysis of inputs and calling method
3. **Return Behavior**: What does it return and how is it used?
4. **WoW Context**: How this relates to WoW game mechanics/systems
5. **Caller Analysis**: How the function is used based on caller context
6. **Data Structures**: WoW-specific structures and types involved
7. **Recommendations**: Practical reverse engineering insights

Be specific to WoW and x86, avoid generic analysis."""

        else:  # data analysis
            system_prompt = """You are an expert x86 reverse engineer specializing in World of Warcraft 3.3.5a (build 12340) binary analysis and data structure analysis.

CRITICAL ANALYSIS GUIDELINES:
1. Focus on understanding the PURPOSE and USAGE of data elements
2. WoW uses many custom data structures, pointers, and offset tables
3. Look for patterns in how data is accessed and used
4. Consider WoW's architecture: client-server, game objects, UI, networking, etc.
5. Be precise about data relationships and usage patterns

ANALYSIS FOCUS:
- What type of data structure or element is this?
- How is this data used in the WoW client?
- What WoW systems might this data be part of?
- What are the relationships between this data and other elements?
- What does the usage pattern tell us about its purpose?

AVOID:
- Generic speculation without evidence
- Assumptions about data without clear usage patterns"""

            user_prompt = f"""Analyze this WoW 3.3.5a data element with full context:

{context}

Provide a focused analysis covering:
1. **Data Type & Purpose**: What type of data is this and what's its purpose?
2. **Usage Pattern**: How is this data accessed and used?
3. **WoW Context**: How this relates to WoW game mechanics/systems
4. **Relationships**: How this data relates to other elements
5. **Structure Analysis**: If it's part of a larger structure, analyze that
6. **Recommendations**: Practical reverse engineering insights

Be specific to WoW and focus on actual usage patterns."""

        # Extract the item name from title for progress dialog
        item_name = title.split(': ', 1)[1] if ': ' in title else title
        
        progress = ProgressDialog("AutoReverse Analysis", f"Analyzing {item_name}...")
        progress.show()
        
        def analysis_thread():
            try:
                print(f"AutoReverse: Starting analysis thread for {item_name}")
                
                # Perform initial analysis
                print(f"AutoReverse: Calling Gemini API for {item_name}")
                initial_response = self.gemini_client._make_request(user_prompt, system_prompt)
                
                print(f"AutoReverse: API response received, length: {len(initial_response) if initial_response else 0}")
                
                if not initial_response:
                    raise ValueError("No response from API")
                
                print(f"AutoReverse: Creating chat history for {item_name}")
                # Create history using dictionaries instead of Content objects
                history = [
                    {
                        'role': 'user',
                        'parts': [{'text': user_prompt}]
                    },
                    {
                        'role': 'model', 
                        'parts': [{'text': initial_response}]
                    }
                ]
                
                print(f"AutoReverse: Starting chat session for {item_name}")
                # Start chat session
                chat_session = self.gemini_client.start_chat(system_instruction=system_prompt, history=history)
                print(f"AutoReverse: Chat session created successfully for {item_name}")
                
                def update_ui():
                    try:
                        print(f"AutoReverse: Updating UI for {item_name}")
                        progress.hide()
                        widget_name = f"AutoReverse_{title.replace(' ', '_').replace(':', '_')}"
                        print(f"AutoReverse: Creating widget: {widget_name}")
                        
                        # Pass prompts to widget for display if enabled
                        prompts = {
                            "system_prompt": system_prompt,
                            "user_prompt": user_prompt
                        }
                        
                        results_widget = AutoReverseResultsWidget(title=title, chat_session=chat_session, prompts=prompts)
                        results_widget.results_text = initial_response
                        print(f"AutoReverse: Widget created, showing...")
                        
                        results_widget.Show(widget_name)
                        self.ui_manager.result_widgets[widget_name] = results_widget
                        print(f"AutoReverse: Widget shown successfully: {widget_name}")
                        
                    except Exception as ui_error:
                        print(f"AutoReverse: Error in UI update: {ui_error}")
                        print(f"AutoReverse: UI error traceback: {traceback.format_exc()}")
                        # Fallback to simple info dialog
                        ida_kernwin.info(f"Analysis Result for {item_name}:\n\n{initial_response}")
                
                print(f"AutoReverse: Scheduling UI update for {item_name}")
                ida_kernwin.execute_sync(update_ui, ida_kernwin.MFF_WRITE)
                
            except Exception as e:
                print(f"AutoReverse: Error in analysis thread: {e}")
                print(f"AutoReverse: Analysis thread traceback: {traceback.format_exc()}")
                def show_error():
                    progress.hide()
                    self.ui_manager.show_error(f"Analysis failed: {str(e)}")
                ida_kernwin.execute_sync(show_error, ida_kernwin.MFF_WRITE)
        
        thread = threading.Thread(target=analysis_thread)
        thread.daemon = True
        thread.start()

    def analyze_structure(self):
        """Analyze a structure"""
        try:
            if not self.struct_analyzer:
                ida_kernwin.warning("Structure analyzer not available")
                return
                
            # Get current address
            ea = ida_kernwin.get_screen_ea()
            
            # Analyze structure asynchronously
            self.ui_manager.show_analysis_async(
                "Structure Analysis",
                self.struct_analyzer.analyze_at_address,
                ea
            )
                
        except Exception as e:
            print(f"AutoReverse: Error analyzing structure: {e}")
            ida_kernwin.warning(f"Error analyzing structure: {e}")

    def rename_variables(self):
        """Rename variables in current function"""
        try:
            if not self.variable_renamer:
                ida_kernwin.warning("Variable renamer not available")
                return
                
            # Get current function
            ea = ida_kernwin.get_screen_ea()
            func = ida_funcs.get_func(ea)
            if not func:
                ida_kernwin.warning("Please position cursor in a function")
                return
            
            # Get function name for display
            func_name = ida_funcs.get_func_name(func.start_ea)
            
            # Rename variables asynchronously
            self.ui_manager.show_analysis_async(
                f"Variable Renaming: {func_name}",
                self.variable_renamer.rename_function_variables,
                func.start_ea
            )
                
        except Exception as e:
            print(f"AutoReverse: Error renaming variables: {e}")
            ida_kernwin.warning(f"Error renaming variables: {e}")

    def set_function_type(self):
        """Set function type based on analysis"""
        try:
            if not self.type_setter:
                ida_kernwin.warning("Type setter not available")
                return
                
            # Get current function
            ea = ida_kernwin.get_screen_ea()
            func = ida_funcs.get_func(ea)
            if not func:
                ida_kernwin.warning("Please position cursor in a function")
                return
            
            # Get function name for display
            func_name = ida_funcs.get_func_name(func.start_ea)
            
            # Set function type asynchronously
            self.ui_manager.show_analysis_async(
                f"Function Type Setting: {func_name}",
                self.type_setter.set_function_type,
                func.start_ea
            )
                
        except Exception as e:
            print(f"AutoReverse: Error setting function type: {e}")
            ida_kernwin.warning(f"Error setting function type: {e}")

    def show_settings(self):
        """Show settings dialog"""
        try:
            if not self.config_manager:
                ida_kernwin.warning("Config manager not available")
                return
            
            # Get current settings
            current_show_prompts = self.config_manager.get_show_prompts()
            current_model = self.config_manager.get_model()
            current_temperature = self.config_manager.get_temperature()
            current_max_tokens = self.config_manager.get_max_tokens()
            
            # Create settings dialog text
            settings_text = f"""AutoReverse Settings

Current Settings:
- Show Prompts in Chat: {'Yes' if current_show_prompts else 'No'}
- Model: {current_model}
- Temperature: {current_temperature}
- Max Tokens: {current_max_tokens}

Recent Updates:
- Context limits reduced for API efficiency
- Rate limiting error handling improved
- Max callers per function: 8 (reduced from 10)
- Max disassembly lines: 80 (reduced from 100)

Would you like to toggle the 'Show Prompts in Chat' setting?
This will show you the exact prompts sent to the AI model in the chat window.

Current setting: {'Enabled' if current_show_prompts else 'Disabled'}

Note: If you're hitting API rate limits, try analyzing smaller functions first."""
            
            # Ask user if they want to toggle the setting
            choice = ida_kernwin.ask_yn(
                ida_kernwin.ASKBTN_YES,
                settings_text
            )
            
            if choice == ida_kernwin.ASKBTN_YES:
                # Toggle the setting
                new_value = not current_show_prompts
                self.config_manager.set_show_prompts(new_value)
                
                status = "enabled" if new_value else "disabled"
                ida_kernwin.info(f"Show Prompts in Chat has been {status}!")
                
        except Exception as e:
            print(f"AutoReverse: Error showing settings: {e}")
            ida_kernwin.warning(f"Error showing settings: {e}")

    def show_about(self):
        """Show about dialog"""
        about_text = """AutoReverse Plugin v1.0

AI-powered reverse engineering assistant using Google Gemini

Features:
- Function analysis and documentation
- Structure analysis and creation
- Variable renaming
- Type setting
- AI-powered insights

Author: AutoReverse Team
License: MIT

To use this plugin:
1. Configure your Google Gemini API key
2. Select a function or structure to analyze
3. Use the menu options to perform analysis

For support, check the plugin documentation.
"""
        ida_kernwin.info(about_text)

    def run(self, arg):
        """Run the plugin"""
        try:
            if not self.initialized:
                ida_kernwin.warning("Plugin not initialized properly")
                return
                
            # Default action - show about dialog
            self.show_about()
            
        except Exception as e:
            print(f"AutoReverse: Error running plugin: {e}")
            ida_kernwin.warning(f"Error running plugin: {e}")

    def term(self):
        """Terminate the plugin"""
        try:
            # Clean up UI resources
            if self.ui_manager:
                self.ui_manager.cleanup()
            
            # Unregister actions
            for action_name in self.menu_items:
                ida_kernwin.unregister_action(action_name)
            
            print("AutoReverse: Plugin terminated")
            
        except Exception as e:
            print(f"AutoReverse: Error during termination: {e}")

def PLUGIN_ENTRY():
    """Plugin entry point"""
    try:
        print("AutoReverse: Plugin entry point called")
        return AutoReversePlugin()
    except Exception as e:
        print(f"AutoReverse: Error in plugin entry: {e}")
        return None 