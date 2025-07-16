"""
Google Gemini API Client for AutoReverse Plugin
Handles communication with the Gemini API
"""

import json
import time
from typing import Optional, Dict, Any

try:
    import google.generativeai as genai
    SDK_AVAILABLE = True
    print("AutoReverse: Using official Google Generative AI SDK")
except ImportError:
    import requests
    SDK_AVAILABLE = False
    print("AutoReverse: Using fallback HTTP requests (install google-generativeai for better performance)")

class GeminiClient:
    def __init__(self, api_key: str = None, config_manager=None):
        self.api_key = api_key
        self.config_manager = config_manager
        
        # Get model from config manager or use default
        if self.config_manager:
            self.model_name = self.config_manager.get_model()
        else:
            self.model_name = "gemini-2.5-pro"  # Fallback default
        
        if SDK_AVAILABLE:
            if api_key:
                genai.configure(api_key=api_key)
            # Configure the model with safety settings
            self.model = None
            self._configure_model()
        else:
            # Fallback to HTTP requests
            self.base_url = f"https://generativelanguage.googleapis.com/v1/models/{self.model_name}:generateContent"
            self.session = requests.Session()
            self.session.headers.update({
                'Content-Type': 'application/json',
            })
    
    def set_api_key(self, api_key: str):
        """Set the API key"""
        self.api_key = api_key
        if SDK_AVAILABLE:
            genai.configure(api_key=api_key)
            self._configure_model()
    
    def set_model(self, model_name: str):
        """Set the model name"""
        self.model_name = model_name
        if self.config_manager:
            self.config_manager.set_model(model_name)
        
        # Update the base URL for HTTP requests
        if not SDK_AVAILABLE:
            self.base_url = f"https://generativelanguage.googleapis.com/v1/models/{self.model_name}:generateContent"
        
        # Reconfigure the model
        self._configure_model()
    
    def get_model(self) -> str:
        """Get the current model name"""
        return self.model_name
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the current model"""
        if self.config_manager:
            return self.config_manager.get_model_info(self.model_name)
        return {}
    
    def _configure_model(self):
        """Configure the Gemini model with safety settings"""
        if not SDK_AVAILABLE or not self.api_key:
            return
            
        try:
            # Configure safety settings to block none - ALL categories
            # Try both string format and enum format for maximum compatibility
            try:
                # Try using proper enums first
                import google.generativeai.types as genai_types
                safety_settings = [
                    {"category": genai_types.HarmCategory.HARM_CATEGORY_HARASSMENT, "threshold": genai_types.HarmBlockThreshold.BLOCK_NONE},
                    {"category": genai_types.HarmCategory.HARM_CATEGORY_HATE_SPEECH, "threshold": genai_types.HarmBlockThreshold.BLOCK_NONE},
                    {"category": genai_types.HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT, "threshold": genai_types.HarmBlockThreshold.BLOCK_NONE},
                    {"category": genai_types.HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT, "threshold": genai_types.HarmBlockThreshold.BLOCK_NONE},
                ]
                print("AutoReverse: Using proper enums for safety settings")
            except Exception as enum_error:
                # Fallback to string format
                safety_settings = [
                    {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_CIVIC_INTEGRITY", "threshold": "BLOCK_NONE"}
                ]
                print(f"AutoReverse: Using string format for safety settings (enum error: {enum_error})")
            
            print("AutoReverse: Configuring safety settings to BLOCK_NONE for all categories")
            
            # Configure generation parameters
            generation_config = genai.types.GenerationConfig(
                temperature=0.7,
                top_k=1,
                top_p=1,
                max_output_tokens=65535,
            )
            
            self.model = genai.GenerativeModel(
                model_name=self.model_name,
                safety_settings=safety_settings,
                generation_config=generation_config
            )
            
            print(f"AutoReverse: Configured model: {self.model_name}")
            
        except Exception as e:
            print(f"AutoReverse: Error configuring model: {e}")
            self.model = None
    
    def _handle_rate_limit_error(self, error_msg: str) -> str:
        """Handle rate limiting errors with helpful suggestions"""
        suggestions = []
        
        # Check if it's a free tier limit
        if "free" in error_msg.lower() or "FreeTier" in error_msg:
            suggestions.append("**Free Tier Limit**: You've exceeded the free tier quota")
            suggestions.append("• Consider upgrading to a paid plan for higher limits")
            suggestions.append("• Wait 24 hours for quota reset")
        
        # Check if it's input token limit
        if "input_token" in error_msg.lower():
            suggestions.append("**Large Context**: The function has too many cross-references")
            suggestions.append("• Try analyzing a smaller function first")
            suggestions.append("• Use 'gemini-2.0-flash-exp' model (lower limits but faster)")
        
        # Check if it's per-minute limit
        if "PerMinute" in error_msg:
            suggestions.append("**Rate Limit**: Too many requests per minute")
            suggestions.append("• Wait 1-2 minutes before trying again")
            suggestions.append("• Consider analyzing functions with fewer XREFs")
        
        error_response = f"""🚫 **API Rate Limit Exceeded**

**Error Details:**
{error_msg}

**Suggestions:**
{chr(10).join(suggestions)}

**Current Function Impact:**
This function likely has many cross-references (XREFs), creating a very large context that exceeds API limits.

**Immediate Solutions:**
1. **Wait and Retry**: Wait 1-2 minutes and try again
2. **Smaller Functions**: Try analyzing functions with fewer callers
3. **Upgrade API**: Consider a paid Gemini API plan for higher limits

**Context Optimization:**
The plugin now limits context to 10 callers maximum, but this function may still be too large for the free tier."""
        
        return error_response
    
    def _make_request(self, prompt: str, system_prompt: str = None) -> Optional[str]:
        """Make a request to the Gemini API"""
        if not self.api_key:
            print("Error: No API key configured")
            return None
        
        # Prepare the full prompt
        full_prompt = prompt
        if system_prompt:
            full_prompt = f"{system_prompt}\n\n{prompt}"
        
        if SDK_AVAILABLE and self.model:
            return self._make_request_sdk(full_prompt)
        else:
            return self._make_request_http(full_prompt)
    
    def _make_request_sdk(self, prompt: str) -> Optional[str]:
        """Make a request using the official Google Generative AI SDK"""
        try:
            response = self.model.generate_content(prompt)
            
            # Check if response was blocked or incomplete
            if not response.candidates:
                print("No response candidates returned")
                return None
            
            candidate = response.candidates[0]
            if hasattr(candidate, 'finish_reason'):
                if candidate.finish_reason == 3:  # SAFETY (correct code)
                    print("AutoReverse: Response blocked by safety filters despite BLOCK_NONE settings!")
                    print(f"AutoReverse: Safety ratings: {getattr(candidate, 'safety_ratings', 'No safety ratings')}")
                    print(f"AutoReverse: Full candidate: {candidate}")
                    return "⚠️ Response blocked by safety filters despite BLOCK_NONE settings.\n\nThis may be a Gemini API limitation. Try:\n1. Rephrasing your request\n2. Using a different function\n3. Switching to Gemini 2.5 Flash model\n\nNote: All safety filters are set to BLOCK_NONE but the API may still have some restrictions."
                elif candidate.finish_reason == 4:  # RECITATION  
                    print("AutoReverse: Response blocked due to recitation")
                    return "Response blocked due to recitation concerns. Try rephrasing your request."
                elif candidate.finish_reason == 2:  # MAX_TOKENS
                    print("AutoReverse: Response truncated due to max tokens limit")
                    # Continue to return the truncated response - it's still useful
                elif candidate.finish_reason != 1:  # Not STOP (successful completion)
                    print(f"AutoReverse: Response incomplete, finish_reason: {candidate.finish_reason}")
                    print(f"AutoReverse: Finish reason codes: 1=STOP, 2=MAX_TOKENS, 3=SAFETY, 4=RECITATION, 5=OTHER")
                    # Don't return None - try to get the text anyway
            
            # Try to get the text content - handle MAX_TOKENS case
            try:
                # For complete responses, try the quick accessor first
                if candidate.finish_reason == 1 and hasattr(response, 'text') and response.text:
                    return response.text
            except Exception as e:
                print(f"AutoReverse: response.text accessor failed: {e}")
            
            # For truncated responses or when quick accessor fails, get text from candidate directly
            if candidate.content and candidate.content.parts:
                text_content = candidate.content.parts[0].text
                
                # Add truncation warning for MAX_TOKENS responses
                if candidate.finish_reason == 2:  # MAX_TOKENS
                    text_content += "\n\n⚠️ **Note: Response was truncated due to length limits. The analysis above may be incomplete.**"
                    
                return text_content
            else:
                print(f"AutoReverse: No valid text in response candidate: {candidate}")
                return None
                
        except Exception as e:
            error_msg = str(e)
            print(f"SDK API request failed: {e}")
            
            # Handle rate limiting specifically
            if "429" in error_msg or "quota" in error_msg.lower() or "rate" in error_msg.lower():
                return self._handle_rate_limit_error(error_msg)
            
            return None
    
    def _make_request_http(self, prompt: str) -> Optional[str]:
        """Make a request using HTTP requests (fallback)"""
        try:
            payload = {
                "contents": [{
                    "parts": [{
                        "text": prompt
                    }]
                }],
                "generationConfig": {
                    "temperature": 0.7,
                    "topK": 1,
                    "topP": 1,
                    "maxOutputTokens": 65535,
                    "stopSequences": []
                },
                "safetySettings": [
                    {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_CIVIC_INTEGRITY", "threshold": "BLOCK_NONE"}
                ]
            }
            
            # Make the request with longer timeout
            url = f"{self.base_url}?key={self.api_key}"
            response = self.session.post(url, json=payload, timeout=60)
            
            if response.status_code == 200:
                result = response.json()
                if 'candidates' in result and len(result['candidates']) > 0:
                    candidate = result['candidates'][0]
                    if 'content' in candidate and 'parts' in candidate['content']:
                        return candidate['content']['parts'][0]['text']
                    else:
                        print(f"Unexpected response format: {result}")
                        return None
                else:
                    print(f"No candidates in response: {result}")
                    return None
            else:
                error_msg = f"HTTP {response.status_code}: {response.text}"
                print(f"API request failed: {error_msg}")
                
                # Handle rate limiting for HTTP requests
                if response.status_code == 429 or "quota" in response.text.lower():
                    return self._handle_rate_limit_error(error_msg)
                
                return None
                
        except Exception as e:
            print(f"HTTP API request failed: {e}")
            return None
    
    def analyze_function(self, func_name: str, code: str) -> Optional[str]:
        """Analyze a function using Gemini - DEPRECATED - Use analyze_function_with_context instead"""
        return self.analyze_function_with_context(func_name, code, None)
    
    def analyze_function_with_context(self, func_name: str, code: str, context: str = None) -> Optional[str]:
        """Analyze a function with full context using Gemini"""
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

REQUIRED OUTPUT FORMAT:
CRITICAL: Always end your analysis with a copy-pastable type declaration in this EXACT format:

Type Declaration:
return_type function_name(parameter_types);

EXAMPLES:
Type Declaration:
void FrameScript_SerializeStringOrNil(lua_State* L, const char* str);

Type Declaration:
int *FrameScript_SerializeStringOrNil(int, char *);

Type Declaration:
void appendFormattedString(lua_State* L, const char* str, size_t len);

DO NOT use markdown code blocks, DO NOT add extra formatting, DO NOT add explanations after the declaration.
Just provide the plain text declaration that can be copied directly into IDA Pro.

AVOID:
- False positive bug reports
- Speculation about uninitialized variables without clear evidence
- Generic security warnings
- Theoretical vulnerabilities"""

        if context:
            prompt = f"""Analyze this WoW 3.3.5a function with full context:

{context}

Provide a focused analysis covering:
1. **Function Purpose**: What does this function do in WoW's context?
2. **Parameters & Calling Convention**: Analysis of inputs and calling method
3. **Return Behavior**: What does it return and how is it used?
4. **WoW Context**: How this relates to WoW game mechanics/systems
5. **Caller Analysis**: How the function is used based on caller context
6. **Data Structures**: WoW-specific structures and types involved
7. **Recommendations**: Practical reverse engineering insights

CRITICAL: End with EXACT format for IDA Pro:

Type Declaration:
return_type function_name(parameter_types);

Examples:
Type Declaration:
void FrameScript_SerializeStringOrNil(lua_State* L, const char* str);

Type Declaration:
int *FrameScript_SerializeStringOrNil(int, char *);

Use the format that matches IDA Pro's current understanding (int, char *) or provide better types (lua_State*, const char*) based on your analysis.

Be specific to WoW and x86, avoid generic analysis."""
        else:
            prompt = f"""Analyze this WoW 3.3.5a decompiled function:

Function: {func_name}
Code:
```c
{code}
```

Provide analysis focused on WoW context and actual behavior.

CRITICAL: End with EXACT format for IDA Pro:

Type Declaration:
return_type function_name(parameter_types);

Examples:
Type Declaration:
void FrameScript_SerializeStringOrNil(lua_State* L, const char* str);

Type Declaration:
int *FrameScript_SerializeStringOrNil(int, char *);

Use the format that matches IDA Pro's current understanding or provide better types based on your analysis."""
        
        return self._make_request(prompt, system_prompt)
    
    def analyze_structure(self, struct_data: str) -> Optional[str]:
        """Analyze a structure using Gemini"""
        system_prompt = """You are a reverse engineering expert specializing in data structure analysis. Analyze the given structure data and provide:
1. Structure purpose and usage
2. Field analysis and types
3. Potential relationships to other structures
4. Common patterns or protocols
5. Suggested field names and types

Be specific and focus on practical reverse engineering insights."""
        
        prompt = f"""Analyze this data structure:

Structure data:
{struct_data}

Please provide a detailed analysis of this structure, including the purpose of each field, likely data types, and how this structure might be used in the program."""
        
        return self._make_request(prompt, system_prompt)
    
    def suggest_variable_names(self, code: str, context: str = None) -> Optional[str]:
        """Suggest better variable names using Gemini"""
        system_prompt = """You are a reverse engineering expert. Analyze the given code and suggest better variable names based on:
1. Variable usage patterns
2. Data flow analysis
3. Function context
4. Common naming conventions

Provide specific rename suggestions in the format: old_name -> new_name"""
        
        prompt = f"""Suggest better variable names for this code:

Code:
```c
{code}
```

Context: {context or 'No additional context'}

Please provide specific variable rename suggestions that would make the code more readable and meaningful."""
        
        return self._make_request(prompt, system_prompt)
    
    def suggest_function_signature(self, func_name: str, code: str) -> Optional[str]:
        """Suggest function signature using Gemini"""
        system_prompt = """You are a reverse engineering expert. Analyze the given function and suggest:
1. Appropriate function signature with parameter names and types
2. Return type
3. Function calling convention if applicable
4. Any special attributes or annotations

Provide the signature in standard C format."""
        
        prompt = f"""Suggest a proper function signature for this decompiled function:

Function name: {func_name}

Code:
```c
{code}
```

Please provide a well-typed function signature that accurately represents the function's interface."""
        
        return self._make_request(prompt, system_prompt)
    
    def test_connection(self) -> bool:
        """Test the API connection"""
        test_prompt = "Hello, this is a test message. Please respond with 'Connection successful'."
        result = self._make_request(test_prompt)
        return result is not None and "successful" in result.lower() 

    def start_chat(self, system_instruction: str = None, history: list = None) -> 'ChatSession':
        """Start a new chat session with optional system instruction and history"""
        if not SDK_AVAILABLE or not self.api_key:
            raise ValueError("Chat functionality requires the official SDK and API key")

        # Configure safety settings using the same approach as _configure_model
        try:
            # Try using proper enums first
            import google.generativeai.types as genai_types
            safety_settings = [
                {"category": genai_types.HarmCategory.HARM_CATEGORY_HARASSMENT, "threshold": genai_types.HarmBlockThreshold.BLOCK_NONE},
                {"category": genai_types.HarmCategory.HARM_CATEGORY_HATE_SPEECH, "threshold": genai_types.HarmBlockThreshold.BLOCK_NONE},
                {"category": genai_types.HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT, "threshold": genai_types.HarmBlockThreshold.BLOCK_NONE},
                {"category": genai_types.HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT, "threshold": genai_types.HarmBlockThreshold.BLOCK_NONE},
            ]
            print("AutoReverse: Using proper enums for chat safety settings")
        except Exception as enum_error:
            # Fallback to string format
            safety_settings = [
                {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_CIVIC_INTEGRITY", "threshold": "BLOCK_NONE"}
            ]
            print(f"AutoReverse: Using string format for chat safety settings (enum error: {enum_error})")

        model_config = {
            'generation_config': genai.types.GenerationConfig(
                temperature=0.7,
                top_k=1,
                top_p=1,
                max_output_tokens=65535,
            ),
            'safety_settings': safety_settings
        }

        if system_instruction:
            model_config['system_instruction'] = system_instruction

        model = genai.GenerativeModel(
            model_name=self.model_name,  # Use the current model name
            **model_config
        )

        chat_kwargs = {}
        if history:
            chat_kwargs['history'] = history

        chat = model.start_chat(**chat_kwargs)
        return ChatSession(chat, model, self.config_manager)

class ChatSession:
    """Wrapper for chat session"""
    def __init__(self, chat, model, config_manager=None):
        self.chat = chat
        self.model = model
        self.config_manager = config_manager
        self.history = chat.history

    def send_message(self, message: str) -> str:
        """Send message and get response"""
        try:
            response = self.chat.send_message(message)
            # Handle response similar to _make_request_sdk
            if response.candidates:
                candidate = response.candidates[0]
                if candidate.content and candidate.content.parts:
                    text = candidate.content.parts[0].text
                    if candidate.finish_reason == 2:  # MAX_TOKENS
                        text += "\n\n⚠️ Response truncated due to token limit."
                    return text
            return None
        except Exception as e:
            print(f"Chat error: {e}")
            return None

    def get_token_count(self) -> int:
        """Get current token count of history"""
        try:
            return self.model.count_tokens(self.history).total_tokens
        except:
            return 0

    def get_max_tokens(self) -> int:
        """Get model's max input tokens based on the model type"""
        if self.config_manager:
            model_name = self.config_manager.get_model()
            # Different models have different context windows
            if "2.5-pro" in model_name:
                return 2097152  # 2M tokens for Gemini 2.5 Pro
            elif "2.0-flash" in model_name:
                return 1048576  # 1M tokens for Gemini 2.0 Flash variants
            elif "2.5-flash" in model_name:
                return 1048576  # 1M tokens for Gemini 2.5 Flash
            else:
                return 1048576  # Default to 1M tokens
        return 2097152  # Default to 2M tokens if no config manager 