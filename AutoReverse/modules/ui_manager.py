"""
UI Manager for AutoReverse Plugin
Handles display of analysis results and user interfaces with custom widgets
"""

import ida_kernwin
import ida_lines
import threading
import time
import re
from typing import Optional, Dict, Any, Callable

from PyQt5.QtWidgets import QVBoxLayout, QTextEdit, QLabel, QSplitter, QLineEdit, QPushButton, QStatusBar, QHBoxLayout
from PyQt5.QtCore import Qt, pyqtSignal, QEvent
from PyQt5.QtGui import QFont, QKeyEvent

class MultiLineTextEdit(QTextEdit):
    """Custom QTextEdit that handles Enter vs Shift+Enter properly"""
    
    # Signal emitted when user wants to send message (Enter without Shift)
    send_message = pyqtSignal()
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptRichText(False)  # Plain text only for input
        
    def keyPressEvent(self, event: QKeyEvent):
        """Handle key press events to customize Enter behavior"""
        if event.key() == Qt.Key_Return or event.key() == Qt.Key_Enter:
            # Check if Shift is pressed
            if event.modifiers() & Qt.ShiftModifier:
                # Shift+Enter: Insert new line (default behavior)
                super().keyPressEvent(event)
            else:
                # Enter alone: Send message
                self.send_message.emit()
                return  # Don't process the event further
        else:
            # All other keys: default behavior
            super().keyPressEvent(event)
    
    def text(self):
        """Get plain text content"""
        return self.toPlainText()
    
    def clear(self):
        """Clear the text content"""
        self.setPlainText("")

class AutoReverseResultsWidget(ida_kernwin.PluginForm):
    """Custom widget for displaying AutoReverse analysis results"""
    
    def __init__(self, title: str = "AutoReverse Results", chat_session=None, prompts=None, is_restored=False):
        super().__init__()
        self.title = title
        self.chat_session = chat_session
        self.results_text = ""
        self.prompts = prompts or {}  # Store system and user prompts
        self.widget = None
        self.is_restored = is_restored  # Flag to distinguish restored vs new sessions
        
    def OnCreate(self, form):
        """Called when the widget is created"""
        try:
            # Get the widget
            self.widget = self.FormToPyQtWidget(form)
            
            # Import Qt modules
            from PyQt5.QtWidgets import QVBoxLayout, QTextEdit, QLabel, QSplitter, QHBoxLayout, QPushButton, QStatusBar
            from PyQt5.QtCore import Qt
            from PyQt5.QtGui import QFont
            
            # Create layout
            layout = QVBoxLayout()
            
            # Create title label
            title_label = QLabel(self.title)
            title_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #4a90e2; margin-bottom: 10px;")
            layout.addWidget(title_label)
            
            # Set font for better code display
            font = QFont("Consolas", 10)
            if not font.exactMatch():
                font = QFont("Courier New", 10)
            
            # Create chat display (main content area)
            self.chat_display = QTextEdit()
            self.chat_display.setReadOnly(True)
            self.chat_display.setFont(font)
            
            # Enable HTML/markdown rendering
            self.chat_display.setAcceptRichText(True)
            
            self.chat_display.setStyleSheet("""
                QTextEdit {
                    background-color: #2b2b2b;
                    color: #e0e0e0;
                    border: 1px solid #555555;
                    border-radius: 4px;
                    padding: 8px;
                    selection-background-color: #4a90e2;
                }
            """)
            layout.addWidget(self.chat_display)

            # Add input area
            input_layout = QVBoxLayout()
            
            # Create a custom multiline text input
            self.input_field = MultiLineTextEdit()
            self.input_field.setPlaceholderText("Type your follow-up question here...\n\nSupports markdown formatting:\n• **bold**, *italic*, `code`\n• Press Enter to send\n• Press Shift+Enter for new line")
            self.input_field.setStyleSheet("""
                QTextEdit {
                    background-color: #3a3a3a;
                    color: #e0e0e0;
                    border: 1px solid #555555;
                    border-radius: 4px;
                    padding: 8px;
                    font-family: 'Consolas', 'Courier New', monospace;
                    font-size: 10pt;
                }
            """)
            self.input_field.setMaximumHeight(120)  # Limit height but allow multiple lines
            self.input_field.setMinimumHeight(80)   # Minimum height for better UX
            
            # Connect the custom send signal
            self.input_field.send_message.connect(self.send_chat_message)
            
            # Send button layout
            button_layout = QHBoxLayout()
            button_layout.addStretch()  # Push button to the right
            
            self.send_button = QPushButton("Send (Enter)")
            self.send_button.setStyleSheet("""
                QPushButton {
                    background-color: #4a90e2;
                    color: white;
                    border: none;
                    border-radius: 4px;
                    padding: 8px 16px;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background-color: #357abd;
                }
            """)
            self.send_button.clicked.connect(self.send_chat_message)
            button_layout.addWidget(self.send_button)
            
            input_layout.addWidget(self.input_field)
            input_layout.addLayout(button_layout)
            layout.addLayout(input_layout)

            # Add status bar for context info
            self.status_bar = QStatusBar()
            self.status_bar.setStyleSheet("background-color: #2b2b2b; color: #e0e0e0;")
            layout.addWidget(self.status_bar)

            # Set initial content
            if self.is_restored and self.chat_session and hasattr(self.chat_session, 'history') and self.chat_session.history:
                # This is a restored chat session - rebuild conversation from history
                self.restore_chat_history()
            else:
                # This is a new analysis - use normal initialization
                if self.prompts:
                    self.show_prompts_if_enabled()
                if self.results_text:
                    self.append_message("AI", self.results_text)
            self.update_status()
            
            self.widget.setLayout(layout)
            
        except Exception as e:
            print(f"Error creating AutoReverse results widget: {e}")
            # Fallback to simple display
            pass
    
    def OnClose(self, form):
        """Called when the widget is closed"""
        pass
    
    def set_results(self, content: str):
        """Set the results content"""
        self.results_text = content
        if hasattr(self, 'chat_display'):
            self.chat_display.clear()
            self.append_message("AI", content)
    
    def append_results(self, content: str):
        """Append to existing results"""
        self.results_text += "\n" + content
        if hasattr(self, 'chat_display'):
            self.append_message("AI", content)

    def append_message(self, sender: str, message: str):
        """Append message to chat display with proper markdown formatting"""
        if sender == "AI":
            color = "#4a90e2"
        elif sender == "System":
            color = "#e24a90"  # Pink for system messages
        else:
            color = "#90e24a"  # Green for user messages
        
        # Convert markdown-style formatting to HTML
        formatted_message = message.replace('\n', '<br>')
        
        # Convert **bold** to <strong>bold</strong>
        formatted_message = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', formatted_message)
        
        # Convert *italic* to <em>italic</em>
        formatted_message = re.sub(r'\*(.*?)\*', r'<em>\1</em>', formatted_message)
        
        # Convert `code` to <code>code</code>
        formatted_message = re.sub(r'`(.*?)`', r'<code style="background-color: #4a4a4a; padding: 2px 4px; border-radius: 3px; font-family: Consolas, monospace;">\1</code>', formatted_message)
        
        # Convert ### headings to bold larger text
        formatted_message = re.sub(r'### (.*?)(<br>|$)', r'<strong style="font-size: 14px; color: #5aa3f0;">\1</strong>\2', formatted_message)
        
        # Add proper HTML formatting
        html_content = f'''
        <div style="margin-bottom: 15px;">
            <span style="color: {color}; font-weight: bold; font-size: 12px;">{sender}:</span>
            <div style="margin-top: 5px; padding: 8px; background-color: #3a3a3a; border-radius: 4px; border-left: 3px solid {color};">
                {formatted_message}
            </div>
        </div>
        '''
        
        # Move cursor to end and insert HTML
        cursor = self.chat_display.textCursor()
        cursor.movePosition(cursor.End)
        self.chat_display.setTextCursor(cursor)
        self.chat_display.insertHtml(html_content)
        
        # Scroll to bottom
        scrollbar = self.chat_display.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def send_chat_message(self):
        """Send user message to chat session"""
        message = self.input_field.text().strip()
        if not message or not self.chat_session:
            return

        self.append_message("User", message)
        self.input_field.clear()

        # Get response async
        def get_response():
            response = self.chat_session.send_message(message)
            if response:
                ida_kernwin.execute_sync(lambda: self.append_message("AI", response), ida_kernwin.MFF_WRITE)
            ida_kernwin.execute_sync(self.update_status, ida_kernwin.MFF_WRITE)

        thread = threading.Thread(target=get_response)
        thread.start()

    def update_status(self):
        """Update token status"""
        if self.chat_session:
            current = self.chat_session.get_token_count()
            max_t = self.chat_session.get_max_tokens()
            
            # Get model info if available
            model_info = ""
            if hasattr(self.chat_session, 'config_manager') and self.chat_session.config_manager:
                model_name = self.chat_session.config_manager.get_model()
                model_data = self.chat_session.config_manager.get_model_info(model_name)
                if model_data:
                    model_info = f" | Model: {model_data.get('display_name', model_name)}"
            
            self.status_bar.showMessage(f"Tokens: {current:,} / {max_t:,}{model_info}")
        else:
            self.status_bar.showMessage("Chat not initialized")
    
    def restore_chat_history(self):
        """Restore chat history from an existing chat session"""
        try:
            if not self.chat_session or not hasattr(self.chat_session, 'history'):
                # Fallback to normal initialization
                self._fallback_to_normal_init()
                return
            
            # Check if history is empty
            if not self.chat_session.history:
                # Fallback to normal initialization
                self._fallback_to_normal_init()
                return
            
            # Show restoration indicator
            self.append_message("System", "**=== RESTORED CHAT SESSION ===**\n\nPrevious conversation has been restored. You can continue chatting below.")
            
            # Show prompts if enabled (for context)
            if self.prompts:
                self.show_prompts_if_enabled()
            
            # Rebuild conversation from chat history
            messages_restored = 0
            for message in self.chat_session.history:
                try:
                    if hasattr(message, 'role') and hasattr(message, 'parts'):
                        role = message.role
                        # Get text content from parts
                        content_parts = []
                        for part in message.parts:
                            if hasattr(part, 'text'):
                                content_parts.append(part.text)
                        
                        if content_parts:
                            content = "\n".join(content_parts)
                            
                            # Map roles to display names
                            if role == 'user':
                                sender = "User"
                            elif role == 'model':
                                sender = "AI"
                            else:
                                sender = role.capitalize()
                            
                            # Add message to display
                            self.append_message(sender, content)
                            messages_restored += 1
                    
                except Exception as msg_error:
                    print(f"Error restoring message: {msg_error}")
                    continue
            
            # If no messages were restored, fall back to normal init
            if messages_restored == 0:
                self._fallback_to_normal_init()
                return
            
            print(f"AutoReverse: Restored {messages_restored} messages from chat history")
            
        except Exception as e:
            print(f"Error restoring chat history: {e}")
            # Fallback to normal initialization
            self._fallback_to_normal_init()

    def _fallback_to_normal_init(self):
        """Fallback to normal initialization when history restoration fails"""
        # Show prompts if enabled
        if self.prompts:
            self.show_prompts_if_enabled()
        
        # Show original results if available
        if self.results_text:
            self.append_message("System", "**Chat session restored** (using original analysis as history was unavailable)")
            self.append_message("AI", self.results_text)
        else:
            self.append_message("System", "**Chat session restored** - you can continue chatting.")

    def show_prompts_if_enabled(self):
        """Show prompts if the setting is enabled"""
        try:
            # Import here to avoid circular imports
            from config_manager import ConfigManager
            config = ConfigManager()
            
            if config.get_show_prompts() and self.prompts:
                if "system_prompt" in self.prompts:
                    self.append_message("System", f"**System Prompt:**\n\n{self.prompts['system_prompt']}")
                if "user_prompt" in self.prompts:
                    self.append_message("User", f"**User Prompt:**\n\n{self.prompts['user_prompt']}")
        except Exception as e:
            print(f"Error showing prompts: {e}")


class ProgressDialog:
    """Simple progress dialog for long-running operations"""
    
    def __init__(self, title: str, message: str):
        self.title = title
        self.message = message
        self.cancelled = False
        
    def show(self):
        """Show progress dialog"""
        try:
            # Simple progress indicator using IDA's wait box
            ida_kernwin.show_wait_box(f"{self.title}\n\n{self.message}\n\nPlease wait...")
        except:
            pass
    
    def hide(self):
        """Hide progress dialog"""
        try:
            ida_kernwin.hide_wait_box()
        except:
            pass


class UIManager:
    def __init__(self):
        self.result_widgets = {}
        self.active_threads = []
        
    def show_analysis_result(self, title: str, content: str) -> None:
        """Show analysis result in a custom widget"""
        try:
            # Create unique widget name
            widget_name = f"AutoReverse_{title.replace(' ', '_')}"
            
            # Check if widget already exists
            existing_widget = ida_kernwin.find_widget(widget_name)
            if existing_widget:
                # Update existing widget
                if widget_name in self.result_widgets:
                    self.result_widgets[widget_name].set_results(content)
                    ida_kernwin.activate_widget(existing_widget, True)
                    return
            
            # Create new widget
            results_widget = AutoReverseResultsWidget(title)
            results_widget.results_text = content
            
            # Show the widget
            try:
                results_widget.Show(widget_name)
                self.result_widgets[widget_name] = results_widget
                print(f"AutoReverse: Created results widget '{title}'")
            except Exception as e:
                print(f"AutoReverse: Failed to create widget: {e}")
                # Fallback to info dialog
                self._show_fallback_dialog(title, content)
                
        except Exception as e:
            print(f"Error showing analysis result: {e}")
            self._show_fallback_dialog(title, content)
    
    def _show_fallback_dialog(self, title: str, content: str):
        """Fallback to simple dialog if widget creation fails"""
        ida_kernwin.info(f"{title}\n\n{content}")
    
    def show_analysis_async(self, title: str, analysis_func: Callable, *args, **kwargs) -> None:
        """Show analysis result asynchronously without blocking IDA Pro"""
        try:
            # Show progress dialog
            progress = ProgressDialog("AutoReverse Analysis", f"Analyzing {title}...")
            progress.show()
            
            # Create thread for analysis
            def analysis_thread():
                try:
                    # Perform analysis
                    result = analysis_func(*args, **kwargs)

                    # Schedule UI update on main thread
                    def update_ui():
                        progress.hide()
                        if result:
                            self.show_analysis_result(title, result)
                        else:
                            self.show_error("Analysis failed.")
                    
                    # Execute UI update on main thread
                    ida_kernwin.execute_sync(update_ui, ida_kernwin.MFF_WRITE)
                    
                except Exception as e:
                    print(f"Error in analysis thread: {e}")
                    # Schedule error display on main thread
                    def show_error():
                        progress.hide()
                        self.show_error(f"Analysis failed: {e}")
                    
                    ida_kernwin.execute_sync(show_error, ida_kernwin.MFF_WRITE)
            
            # Start analysis thread
            thread = threading.Thread(target=analysis_thread)
            thread.daemon = True
            thread.start()
            
            # Keep track of active threads
            self.active_threads.append(thread)
            
        except Exception as e:
            print(f"Error starting async analysis: {e}")
            self.show_error(f"Failed to start analysis: {e}")
    
    def show_error(self, message: str) -> None:
        """Show error message"""
        ida_kernwin.warning(f"AutoReverse Error: {message}")
    
    def show_info(self, message: str) -> None:
        """Show info message"""
        ida_kernwin.info(f"AutoReverse: {message}")
    
    def cleanup(self):
        """Clean up resources"""
        try:
            # Close all result widgets
            for widget_name, widget in self.result_widgets.items():
                try:
                    widget.Close()
                except:
                    # Try alternative close method
                    try:
                        widget.close()
                    except:
                        pass
            
            self.result_widgets.clear()
            
            # Wait for threads to finish (with timeout)
            for thread in self.active_threads:
                if thread.is_alive():
                    thread.join(timeout=1.0)
            
            self.active_threads.clear()
            
        except Exception as e:
            print(f"Error during UI cleanup: {e}") 