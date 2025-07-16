"""
Configuration Manager for AutoReverse Plugin
Handles API keys and plugin settings
"""

import os
import json
from pathlib import Path
import ida_kernwin

class ConfigManager:
    def __init__(self):
        self.config_file = Path.home() / ".autoreverse_config.json"
        self.config = self.load_config()
        
        # Available models with their rate limits and capabilities
        self.available_models = {
            "gemini-2.5-pro": {
                "display_name": "Gemini 2.5 Pro",
                "rpm": 5,
                "tpm": 250000,
                "rpd": 100,
                "description": "Best for complex analysis (lower rate limits)",
                "recommended_for": "Complex reverse engineering tasks"
            },
            "gemini-2.5-flash": {
                "display_name": "Gemini 2.5 Flash", 
                "rpm": 10,
                "tpm": 250000,
                "rpd": 250,
                "description": "Faster with good capabilities", 
                "recommended_for": "General purpose analysis"
            },
            "gemini-2.0-flash-exp": {
                "display_name": "Gemini 2.0 Flash (Experimental)",
                "rpm": 15,
                "tpm": 1000000,
                "rpd": 200,
                "description": "High throughput, good for frequent requests",
                "recommended_for": "Analyzing many functions"
            },
            "gemini-2.0-flash-thinking-exp": {
                "display_name": "Gemini 2.0 Flash Thinking (Experimental)",
                "rpm": 15,
                "tpm": 1000000, 
                "rpd": 200,
                "description": "Enhanced reasoning capabilities",
                "recommended_for": "Complex logic analysis"
            }
        }
    
    def load_config(self):
        """Load configuration from file"""
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            print(f"Error loading config: {e}")
        
        return {
            "api_key": "",
            "model": "gemini-2.5-pro",  # Updated default to match current best practices
            "temperature": 0.7,
            "max_tokens": 4096,
            "show_prompts": False
        }
    
    def save_config(self):
        """Save configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving config: {e}")
            return False
    
    def get_api_key(self):
        """Get the API key"""
        return self.config.get("api_key", "")
    
    def set_api_key(self, api_key):
        """Set the API key"""
        self.config["api_key"] = api_key
        return self.save_config()
    
    def get_model(self):
        """Get the model name"""
        return self.config.get("model", "gemini-2.5-pro")
    
    def set_model(self, model):
        """Set the model name"""
        if model in self.available_models:
            self.config["model"] = model
            return self.save_config()
        else:
            print(f"Warning: Unknown model {model}, using default")
            return False
    
    def get_available_models(self):
        """Get all available models with their information"""
        return self.available_models
    
    def get_model_info(self, model_name=None):
        """Get information about a specific model or the current model"""
        if model_name is None:
            model_name = self.get_model()
        return self.available_models.get(model_name, {})
    
    def get_recommended_model_for_task(self, task_type="general"):
        """Get recommended model based on task type"""
        recommendations = {
            "general": "gemini-2.5-flash",
            "complex": "gemini-2.5-pro", 
            "bulk": "gemini-2.0-flash-exp",
            "reasoning": "gemini-2.0-flash-thinking-exp"
        }
        return recommendations.get(task_type, "gemini-2.5-pro")
    
    def get_temperature(self):
        """Get the temperature setting"""
        return self.config.get("temperature", 0.7)
    
    def set_temperature(self, temperature):
        """Set the temperature setting"""
        self.config["temperature"] = temperature
        return self.save_config()
    
    def get_max_tokens(self):
        """Get the max tokens setting"""
        return self.config.get("max_tokens", 4096)
    
    def set_max_tokens(self, max_tokens):
        """Set the max tokens setting"""
        self.config["max_tokens"] = max_tokens
        return self.save_config()
    
    def get_all_settings(self):
        """Get all settings"""
        return self.config.copy()
    
    def update_settings(self, settings):
        """Update multiple settings"""
        self.config.update(settings)
        return self.save_config()
    
    def get_show_prompts(self):
        """Get the show prompts setting"""
        return self.config.get("show_prompts", False)
    
    def set_show_prompts(self, show_prompts):
        """Set the show prompts setting"""
        self.config["show_prompts"] = show_prompts
        return self.save_config()
        
    def get_rate_limit_info(self, model_name=None):
        """Get rate limit information for a model"""
        model_info = self.get_model_info(model_name)
        if model_info:
            return f"Rate Limits - RPM: {model_info['rpm']}, TPM: {model_info['tpm']:,}, RPD: {model_info['rpd']}"
        return "Rate limit information not available" 