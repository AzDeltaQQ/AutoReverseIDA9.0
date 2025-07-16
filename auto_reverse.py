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

class AutoReversePopupHook(ida_kernwin.UI_Hooks):
    """Popup hook to add context menu items"""
    def __init__(self, plugin):
        ida_kernwin.UI_Hooks.__init__(self)
        self.plugin = plugin
        self.context_actions = [
            ("AutoReverse:AnalyzeFunction", "AutoReverse: Analyze Current Item"),
                            ("AutoReverse:AddToChat", "AutoReverse: Add Item to Open Chat"),
            ("AutoReverse:AnalyzeStructure", "AutoReverse: Analyze Structure"),
            ("AutoReverse:RenameVariables", "AutoReverse: Rename Variables"),
            ("AutoReverse:SetFunctionType", "AutoReverse: Set Function Type")
        ]
    
    def finish_populating_widget_popup(self, widget, popup):
        """Add AutoReverse items to context menu"""
        try:
            # Check if this is a relevant widget
            widget_type = ida_kernwin.get_widget_type(widget)
            widget_title = ida_kernwin.get_widget_title(widget)
            
            # Add items to relevant views
            if (widget_type == ida_kernwin.BWN_DISASM or 
                widget_type == ida_kernwin.BWN_PSEUDOCODE or
                "IDA View" in widget_title or
                "Pseudocode" in widget_title):
                
                # Add separator
                ida_kernwin.attach_action_to_popup(widget, popup, None, None)
                
                # Add our actions
                for action_name, label in self.context_actions:
                    ida_kernwin.attach_action_to_popup(widget, popup, action_name, None)
                    
                return 0
                
        except Exception as e:
            print(f"AutoReverse: Error in popup hook: {e}")
            
        return 0

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
        self.popup_hook = None
        self.closed_chat_sessions = {}  # Store closed chat sessions for restoration
        
        print("AutoReverse: Plugin initialized")

    def init(self):
        """Initialize the plugin"""
        try:
            print("AutoReverse: Initializing plugin components...")
            
            if not MODULES_LOADED:
                print("AutoReverse: Modules not loaded, creating fallback menu")
                self.create_fallback_menu()
                # Still install popup hook even in fallback mode
                self.popup_hook = AutoReversePopupHook(self)
                self.popup_hook.hook()
                print("AutoReverse: Installed popup hook for context menus (fallback mode)")
                self.initialized = True
                return ida_idaapi.PLUGIN_KEEP
            
            # Initialize components
            self.config_manager = ConfigManager()
            self.gemini_client = GeminiClient(config_manager=self.config_manager)  # Pass config manager
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
            
            # Install popup hook for context menus
            self.popup_hook = AutoReversePopupHook(self)
            self.popup_hook.hook()
            print("AutoReverse: Installed popup hook for context menus")
            
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
                ("AutoReverse:AddToChat", "AutoReverse: Add Item to Open Chat", self.add_function_to_chat),
                ("AutoReverse:RestoreChat", "AutoReverse: Restore Chat Session", self.restore_chat_session),
                ("AutoReverse:AnalyzeStructure", "AutoReverse: Analyze Structure", self.analyze_structure),
                ("AutoReverse:RenameVariables", "AutoReverse: Rename Variables", self.rename_variables),
                ("AutoReverse:SetFunctionType", "AutoReverse: Set Function Type", self.set_function_type),
                ("AutoReverse:About", "AutoReverse: About", self.show_about),
            ]
            
            # Define which actions should appear in context menus
            context_menu_actions = [
                "AutoReverse:AnalyzeFunction",
                "AutoReverse:AddToChat",
                "AutoReverse:AnalyzeStructure", 
                "AutoReverse:RenameVariables",
                "AutoReverse:SetFunctionType"
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
                    
                    # Attach to Edit menu
                    if ida_kernwin.attach_action_to_menu("Edit/", action_name, ida_kernwin.SETMENU_APP):
                        print(f"AutoReverse: Created menu item: {label}")
                    else:
                        print(f"AutoReverse: Failed to attach menu item: {label}")
                    
                    # Attach relevant actions to context menus
                    if action_name in context_menu_actions:
                        try:
                            # Try multiple window types for IDA Pro 9.0 compatibility
                            popup_types = [
                                "IDA View-A",      # Main disassembly view
                                "IDA View-B",      # Secondary disassembly view
                                "Pseudocode-A",    # Main pseudocode view
                                "Pseudocode-B",    # Secondary pseudocode view
                                "Functions",       # Functions window
                                "Disassembly",     # Generic disassembly
                                "Decompiler"       # Generic decompiler
                            ]
                            
                            attached_count = 0
                            for popup_type in popup_types:
                                try:
                                    if ida_kernwin.attach_action_to_popup(None, None, action_name, popup_type):
                                        print(f"AutoReverse: Attached {action_name} to {popup_type} context menu")
                                        attached_count += 1
                                except Exception as popup_e:
                                    # Silently ignore - this is expected to fail in IDA Pro 9.0
                                    pass
                            
                            if attached_count == 0:
                                # Don't show warning since popup hook method will handle this
                                pass
                                
                        except Exception as ctx_e:
                            print(f"AutoReverse: Error attaching {action_name} to context menu: {ctx_e}")
                    
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
        
        print(f"AutoReverse: Gathering comprehensive context for data element {name}...")
        
        # Gather comprehensive data context using ContextGatherer
        context_data = self.context_gatherer.gather_data_context(
            ea,
            max_xref_lines=50,  # Lines of disassembly per referencing function
            max_xrefs=8        # Max number of references to analyze
        )
        
        if "error" in context_data:
            ida_kernwin.warning(f"Context gathering failed: {context_data['error']}")
            return
        
        # Format context for AI analysis
        formatted_context = self.context_gatherer.format_data_context_for_ai(context_data)
        
        self._perform_analysis(f"Data Analysis: {name}", formatted_context, "data")

    def add_function_to_chat(self):
        """Add the current function or data item to an existing open chat"""
        try:
            if not self.gemini_client or not self.context_gatherer:
                ida_kernwin.warning("Required components not available")
                return
                
            # Get current address
            ea = ida_kernwin.get_screen_ea()
            
            # Check if it's a function or data
            func = ida_funcs.get_func(ea)
            if not func:
                # Not in a function - check if it's a data element
                flags = ida_bytes.get_flags(ea)
                if not (ida_bytes.is_data(flags) or ida_bytes.is_unknown(flags)):
                    ida_kernwin.warning("Please position cursor on a function or data element")
                    return
                
                # It's a data element - we'll handle this case below
                item_type = "data"
                item_name = ida_name.get_name(ea) or f"data_{ea:X}"
            else:
                # It's a function
                item_type = "function" 
                item_name = ida_funcs.get_func_name(func.start_ea)
                
            # Find existing chat widgets
            if not self.ui_manager or not hasattr(self.ui_manager, 'result_widgets'):
                ida_kernwin.warning("No chat sessions found")
                return
                
            chat_widgets = []
            for widget_name, widget in self.ui_manager.result_widgets.items():
                if hasattr(widget, 'chat_session') and widget.chat_session:
                    chat_widgets.append((widget_name, widget))
            
            if not chat_widgets:
                ida_kernwin.warning("No open chat sessions found. Please use 'Analyze Current Item' first to create a chat session.")
                return
            
            # Select which chat to add to
            target_widget = None
            if len(chat_widgets) == 1:
                # Only one chat - use it
                target_widget = chat_widgets[0][1]
                print(f"AutoReverse: Adding {item_type} to chat: {chat_widgets[0][0]}")
            else:
                # Multiple chats - let user choose
                choices = []
                for i, (widget_name, widget) in enumerate(chat_widgets):
                    # Extract item name from widget name for display
                    display_name = widget_name.replace("AutoReverse_", "").replace("_", " ")
                    choices.append(f"{i + 1}. {display_name}")
                
                choice_text = "Multiple chat sessions found. Choose which one to add to:\n\n" + "\n".join(choices)
                selected = ida_kernwin.ask_long(1, choice_text + f"\n\nEnter number (1-{len(chat_widgets)}):")
                
                if selected and 1 <= selected <= len(chat_widgets):
                    target_widget = chat_widgets[selected - 1][1]
                    print(f"AutoReverse: Adding {item_type} to selected chat: {chat_widgets[selected - 1][0]}")
                else:
                    ida_kernwin.warning("Invalid selection")
                    return
            
            # Gather context based on item type
            print(f"AutoReverse: Gathering context for {item_type} {item_name} to add to chat...")
            
            if item_type == "function":
                # Gather function context
                context_data = self.context_gatherer.gather_function_context(
                    func.start_ea, 
                    max_disasm_lines=80,
                    max_caller_lines=40,
                    max_callers=8
                )
                
                if "error" in context_data:
                    ida_kernwin.warning(f"Context gathering failed: {context_data['error']}")
                    return
                
                # Format context for AI analysis
                formatted_context = self.context_gatherer.format_context_for_ai(context_data)
                
            else:  # data
                # Gather data context
                context_data = self.context_gatherer.gather_data_context(
                    ea,
                    max_xref_lines=50,
                    max_xrefs=8
                )
                
                if "error" in context_data:
                    ida_kernwin.warning(f"Context gathering failed: {context_data['error']}")
                    return
                
                # Format context for AI analysis
                formatted_context = self.context_gatherer.format_data_context_for_ai(context_data)
            
            # Add to existing chat
            self._add_to_existing_chat(target_widget, item_name, formatted_context)
                
        except Exception as e:
            print(f"AutoReverse: Error adding item to chat: {e}")
            print(f"AutoReverse: Error traceback: {traceback.format_exc()}")
            ida_kernwin.warning(f"Error adding item to chat: {e}\n\nCheck IDA Output window for detailed error information.")

    def _add_to_existing_chat(self, target_widget, item_name, context):
        """Add function or data context to an existing chat widget"""
        try:
            # Prepare the message to add to chat
            user_message = f"Please also analyze this related item '{item_name}' and explain how it connects to our previous discussion:\n\n{context}"
            
            # Show prompts if enabled (before sending)
            try:
                from config_manager import ConfigManager
                config = ConfigManager()
                if config.get_show_prompts():
                    # Show what we're sending to the AI
                    if hasattr(target_widget, 'append_message'):
                        target_widget.append_message("System", f"**Adding Function Prompt:**\n\n{user_message}")
            except Exception as prompt_error:
                print(f"AutoReverse: Error showing add-to-chat prompt: {prompt_error}")
            
            # Show progress
            progress = ProgressDialog("Adding to Chat", f"Adding {item_name} to existing chat...")
            progress.show()
            
            def add_to_chat_thread():
                try:
                    print(f"AutoReverse: Sending additional item {item_name} to chat")
                    
                    # Send message to existing chat session
                    response = target_widget.chat_session.send_message(user_message)
                    
                    if not response:
                        raise ValueError("No response from chat session")
                    
                    print(f"AutoReverse: Received response for {item_name}, length: {len(response)}")
                    
                    def update_chat_ui():
                        try:
                            progress.hide()
                            
                            # Add the user message and response to the chat display
                            if hasattr(target_widget, 'append_message'):
                                # Check if we should show the user message (if prompts weren't already shown)
                                try:
                                    from config_manager import ConfigManager
                                    config = ConfigManager()
                                    show_prompts = config.get_show_prompts()
                                except:
                                    show_prompts = False
                                
                                # Only show user message if prompts are disabled (to avoid duplication)
                                if not show_prompts:
                                    target_widget.append_message("User", f"**Added Item**: {item_name}\n\nPlease analyze this item and explain how it connects to our previous discussion.")
                                
                                target_widget.append_message("AI", response)
                            else:
                                # Fallback: append to results_text
                                if hasattr(target_widget, 'results_text'):
                                    target_widget.results_text += f"\n\n=== ADDED ITEM: {item_name} ===\n\n{response}"
                                    if hasattr(target_widget, 'update_display'):
                                        target_widget.update_display()
                            
                            # Bring the chat window to front
                            try:
                                # Try PyQt methods first
                                if hasattr(target_widget.widget, 'activateWindow'):
                                    target_widget.widget.activateWindow()
                                    target_widget.widget.raise_()
                                elif hasattr(target_widget, 'Activate'):
                                    target_widget.Activate()
                            except Exception as activate_error:
                                print(f"AutoReverse: Could not activate window: {activate_error}")
                                # Continue anyway - the message was still added
                            
                            print(f"AutoReverse: Successfully added {item_name} to chat")
                            
                        except Exception as ui_error:
                            print(f"AutoReverse: Error updating chat UI: {ui_error}")
                            # Fallback to info dialog
                            ida_kernwin.info(f"Added {item_name} to chat:\n\n{response[:500]}...")
                    
                    ida_kernwin.execute_sync(update_chat_ui, ida_kernwin.MFF_WRITE)
                    
                except Exception as e:
                    print(f"AutoReverse: Error in add to chat thread: {e}")
                    print(f"AutoReverse: Add to chat thread traceback: {traceback.format_exc()}")
                    def show_error():
                        progress.hide()
                        self.ui_manager.show_error(f"Failed to add item to chat: {str(e)}")
                    ida_kernwin.execute_sync(show_error, ida_kernwin.MFF_WRITE)
            
            thread = threading.Thread(target=add_to_chat_thread)
            thread.daemon = True
            thread.start()
            
        except Exception as e:
            print(f"AutoReverse: Error setting up add to chat: {e}")
            ida_kernwin.warning(f"Error setting up add to chat: {e}")

    def restore_chat_session(self):
        """Restore a previously closed chat session"""
        try:
            if not self.closed_chat_sessions:
                ida_kernwin.info("No closed chat sessions available to restore.")
                return
            
            # If only one closed session, restore it directly
            if len(self.closed_chat_sessions) == 1:
                session_name = list(self.closed_chat_sessions.keys())[0]
                self._restore_specific_chat(session_name)
                return
            
            # Multiple sessions - let user choose
            choices = []
            session_names = list(self.closed_chat_sessions.keys())
            
            for i, session_name in enumerate(session_names):
                # Clean up the display name
                display_name = session_name.replace("AutoReverse_", "").replace("_", " ")
                choices.append(f"{i + 1}. {display_name}")
            
            choice_text = "Multiple closed chat sessions found. Choose which one to restore:\n\n" + "\n".join(choices)
            selected = ida_kernwin.ask_long(1, choice_text + f"\n\nEnter number (1-{len(session_names)}):")
            
            if selected and 1 <= selected <= len(session_names):
                session_name = session_names[selected - 1]
                self._restore_specific_chat(session_name)
            else:
                ida_kernwin.warning("Invalid selection")
                
        except Exception as e:
            print(f"AutoReverse: Error restoring chat session: {e}")
            ida_kernwin.warning(f"Error restoring chat session: {e}")

    def _restore_specific_chat(self, session_name):
        """Restore a specific chat session"""
        try:
            if session_name not in self.closed_chat_sessions:
                ida_kernwin.warning(f"Chat session {session_name} not found")
                return
            
            session_data = self.closed_chat_sessions[session_name]
            chat_session = session_data['chat_session']
            title = session_data['title']
            prompts = session_data.get('prompts', {})
            original_results = session_data.get('original_results', '')
            
            print(f"AutoReverse: Restoring chat session: {title}")
            
            # Create new widget with existing chat session (marked as restored)
            widget_name = session_name
            results_widget = AutoReverseResultsWidget(title=title, chat_session=chat_session, prompts=prompts, is_restored=True)
            
            # Set original results as fallback in case history restoration fails
            results_widget.results_text = original_results
            
            # Show the restored widget
            results_widget.Show(widget_name)
            self.ui_manager.result_widgets[widget_name] = results_widget
            
            # Set up close handler for this restored widget
            self._setup_widget_close_handler(results_widget, widget_name)
            
            # Remove from closed sessions (it's now open again)
            del self.closed_chat_sessions[session_name]
            
            print(f"AutoReverse: Successfully restored chat session: {title}")
            ida_kernwin.info(f"Restored chat session: {title}")
            
        except Exception as e:
            print(f"AutoReverse: Error restoring specific chat {session_name}: {e}")
            ida_kernwin.warning(f"Error restoring chat session: {e}")

    def _setup_widget_close_handler(self, widget, widget_name):
        """Set up close handler to save chat session when widget is closed"""
        try:
            # Store original OnClose method
            original_on_close = getattr(widget, 'OnClose', None)
            
            def enhanced_on_close(form):
                try:
                    # Save the chat session before closing
                    if hasattr(widget, 'chat_session') and widget.chat_session:
                        self.closed_chat_sessions[widget_name] = {
                            'chat_session': widget.chat_session,
                            'title': widget.title,
                            'prompts': getattr(widget, 'prompts', {}),
                            'original_results': getattr(widget, 'results_text', '')
                        }
                        print(f"AutoReverse: Saved chat session for restoration: {widget.title}")
                    
                    # Remove from active widgets
                    if widget_name in self.ui_manager.result_widgets:
                        del self.ui_manager.result_widgets[widget_name]
                    
                    # Call original close handler if it exists
                    if original_on_close:
                        original_on_close(form)
                        
                except Exception as close_error:
                    print(f"AutoReverse: Error in close handler: {close_error}")
            
            # Replace the OnClose method
            widget.OnClose = enhanced_on_close
            
        except Exception as e:
            print(f"AutoReverse: Error setting up close handler: {e}")



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
                        
                        # Set up close handler to save chat session when closed
                        self._setup_widget_close_handler(results_widget, widget_name)
                        
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
        """Show advanced settings dialog with model selection and other options"""
        try:
            if not self.config_manager:
                ida_kernwin.warning("Config manager not available")
                return
            
            # Get current settings
            current_model = self.config_manager.get_model()
            current_show_prompts = self.config_manager.get_show_prompts()
            available_models = self.config_manager.get_available_models()
            
            # First, ask what they want to configure
            model_display_name = available_models.get(current_model, {}).get('display_name', current_model)
            
            settings_menu = f"""AutoReverse Settings

Current Settings:
• Model: {model_display_name}
• Show Prompts in Chat: {'Enabled' if current_show_prompts else 'Disabled'}

What would you like to configure?

1. Change AI Model (Gemini 2.5 Pro, Flash, etc.)
2. Toggle Show Prompts in Chat
3. View All Settings Info
0. Cancel

Enter number (1-3) or 0 to cancel:"""
            
            choice = ida_kernwin.ask_long(1, settings_menu)
            
            if choice == 1:
                # Model selection
                self._show_model_selection()
            elif choice == 2:
                # Toggle show prompts
                self._toggle_show_prompts()
            elif choice == 3:
                # Show all settings info
                self._show_all_settings_info()
            elif choice == 0:
                # Cancel
                return
            else:
                ida_kernwin.warning("Invalid selection")
                
        except Exception as e:
            print(f"AutoReverse: Error showing settings: {e}")
            ida_kernwin.warning(f"Error showing settings: {e}")
    
    def _show_model_selection(self):
        """Show model selection dialog"""
        try:
            current_model = self.config_manager.get_model()
            available_models = self.config_manager.get_available_models()
            
            # Create model selection dialog
            model_choices = []
            model_keys = []
            
            for i, (key, info) in enumerate(available_models.items(), 1):
                display_text = f"{i}. {info['display_name']} - {info['description']}"
                rate_info = f"   (RPM: {info['rpm']}, TPM: {info['tpm']:,}, RPD: {info['rpd']})"
                model_choices.append(f"{display_text}\n{rate_info}")
                model_keys.append(key)
            
            # Find current model index
            current_index = 1
            if current_model in model_keys:
                current_index = model_keys.index(current_model) + 1
            
            # Create selection dialog text
            dialog_text = "AutoReverse - Model Selection\n\n"
            dialog_text += "Choose the model for analysis:\n\n"
            dialog_text += "RPM = Requests Per Minute\n"
            dialog_text += "TPM = Tokens Per Minute\n" 
            dialog_text += "RPD = Requests Per Day\n\n"
            dialog_text += "Available Models:\n\n"
            dialog_text += "\n\n".join(model_choices)
            dialog_text += "\n\n"
            dialog_text += "Recommendations:\n"
            dialog_text += "• Complex analysis: Gemini 2.5 Pro\n"
            dialog_text += "• General use: Gemini 2.5 Flash\n"
            dialog_text += "• Bulk analysis: Gemini 2.0 Flash (Experimental)\n"
            dialog_text += "• Reasoning tasks: Gemini 2.0 Flash Thinking\n\n"
            dialog_text += f"Current model: {available_models.get(current_model, {}).get('display_name', current_model)}\n\n"
            dialog_text += f"Enter number (1-{len(model_keys)}) or 0 to cancel:"
            
            # Show model selection dialog
            selected_index = ida_kernwin.ask_long(current_index, dialog_text)
            
            if selected_index and 1 <= selected_index <= len(model_keys):
                selected_model = model_keys[selected_index - 1]
                if selected_model != current_model:
                    # Update model
                    self.config_manager.set_model(selected_model)
                    self.gemini_client.set_model(selected_model)
                    
                    model_info = available_models[selected_model]
                    ida_kernwin.info(f"Model updated to: {model_info['display_name']}\n\n" +
                                   f"Description: {model_info['description']}\n" +
                                   f"Rate Limits: RPM: {model_info['rpm']}, TPM: {model_info['tpm']:,}, RPD: {model_info['rpd']}\n\n" +
                                   f"Recommended for: {model_info['recommended_for']}")
                else:
                    ida_kernwin.info("Model unchanged.")
            elif selected_index == 0:
                # User cancelled
                return
            else:
                ida_kernwin.warning("Invalid selection")
                
        except Exception as e:
            print(f"AutoReverse: Error in model selection: {e}")
            ida_kernwin.warning(f"Error in model selection: {e}")
    
    def _toggle_show_prompts(self):
        """Toggle the show prompts setting"""
        try:
            current_show_prompts = self.config_manager.get_show_prompts()
            
            choice = ida_kernwin.ask_yn(
                ida_kernwin.ASKBTN_YES if current_show_prompts else ida_kernwin.ASKBTN_NO,
                f"Show Prompts in Chat\n\n" +
                f"Current setting: {'Enabled' if current_show_prompts else 'Disabled'}\n\n" +
                f"When enabled, this setting displays the exact prompts sent to the AI model in chat windows. " +
                f"This is useful for understanding what context the AI receives, but makes the chat longer.\n\n" +
                f"Would you like to toggle this setting?\n\n" +
                f"New setting would be: {'Disabled' if current_show_prompts else 'Enabled'}"
            )
            
            if choice == ida_kernwin.ASKBTN_YES:
                new_value = not current_show_prompts
                self.config_manager.set_show_prompts(new_value)
                status = "enabled" if new_value else "disabled"
                ida_kernwin.info(f"Show Prompts in Chat has been {status}!")
            else:
                ida_kernwin.info("Setting unchanged.")
                
        except Exception as e:
            print(f"AutoReverse: Error toggling show prompts: {e}")
            ida_kernwin.warning(f"Error toggling show prompts: {e}")
    
    def _show_all_settings_info(self):
        """Show detailed information about all settings"""
        try:
            current_model = self.config_manager.get_model()
            current_show_prompts = self.config_manager.get_show_prompts()
            available_models = self.config_manager.get_available_models()
            model_info = available_models.get(current_model, {})
            
            info_text = f"""AutoReverse - All Settings

CURRENT CONFIGURATION:
• AI Model: {model_info.get('display_name', current_model)}
• Show Prompts: {'Enabled' if current_show_prompts else 'Disabled'}

CURRENT MODEL DETAILS:
• Description: {model_info.get('description', 'N/A')}
• Rate Limits: RPM: {model_info.get('rpm', 'N/A')}, TPM: {model_info.get('tpm', 'N/A'):,}, RPD: {model_info.get('rpd', 'N/A')}
• Best for: {model_info.get('recommended_for', 'N/A')}

PLUGIN CONTEXT LIMITS:
• Max callers per function: 8 (reduced for API efficiency)
• Max disassembly lines: 80 (reduced for API efficiency)
• Max caller lines: 40 (reduced for API efficiency)

RATE LIMITING INFO:
If you're hitting API rate limits, try:
• Using Gemini 2.0 Flash models (higher limits)
• Analyzing smaller functions first
• Avoiding functions with many cross-references

To modify settings, use 'AutoReverse > Settings' again."""
            
            ida_kernwin.info(info_text)
            
        except Exception as e:
            print(f"AutoReverse: Error showing settings info: {e}")
            ida_kernwin.warning(f"Error showing settings info: {e}")

    def show_about(self):
        """Show about dialog"""
        about_text = """AutoReverse Plugin v1.0

AI-powered reverse engineering assistant using Google Gemini

Features:
- Function analysis and documentation
- Add functions to existing chat sessions
- Restore closed chat sessions
- Structure analysis and creation
- Variable renaming
- Type setting
- AI-powered insights with context

Author: AutoReverse Team
License: MIT

To use this plugin:
1. Configure your Google Gemini API key
2. Select a function or structure to analyze
3. Use the menu options to perform analysis
4. Build context by adding related functions to chats
5. Restore closed chats to continue conversations

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
            
            # Unhook popup hook
            if self.popup_hook:
                self.popup_hook.unhook()
                self.popup_hook = None
                print("AutoReverse: Removed popup hook")
            
            # Detach actions from context menus first
            context_menu_actions = [
                "AutoReverse:AnalyzeFunction",
                "AutoReverse:AddToChat",
                "AutoReverse:AnalyzeStructure", 
                "AutoReverse:RenameVariables",
                "AutoReverse:SetFunctionType"
            ]
            
            for action_name in context_menu_actions:
                try:
                    # Detach from context menus
                    ida_kernwin.detach_action_from_popup(None, None, action_name)
                except:
                    pass  # Ignore errors during cleanup
            
            # Unregister actions
            for action_name in self.menu_items:
                ida_kernwin.unregister_action(action_name)
            
            # Clear closed chat sessions
            self.closed_chat_sessions.clear()
            
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