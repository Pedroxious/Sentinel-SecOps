import os
import shutil
import google.generativeai as genai

def generate_audio_briefing(text_script, date_str, hour_str):
    """
    Generates an audio briefing using the proprietary TTS model and voice Charon.
    Saves to reports/audio/briefing_YYYY-MM-DD_HH.mp3 and copies to reports/audio/latest.mp3
    """
    os.makedirs(os.path.join("reports", "audio"), exist_ok=True)
    
    # Format hour to replace : with - to avoid filename issues on Windows
    hour_clean = hour_str.replace(":", "-")
    filename = f"reports/audio/briefing_{date_str}_{hour_clean}.mp3"
    latest_filename = "reports/audio/latest.mp3"

    print(f"Generating audio briefing with script: {text_script[:100]}...")
    
    try:
        # Define model with voice config
        model = genai.GenerativeModel("gemini-2.5-flash-preview-tts")
        
        # Generation config
        generation_config = {
            "response_modalities": ["AUDIO"],
            "speech_config": {
                "voice_config": {
                    "prebuilt_voice_config": {
                        "voice_name": "Charon"
                    }
                }
            }
        }
        
        response = model.generate_content(
            text_script,
            generation_config=generation_config
        )
        
        # Extract audio bytes from response
        audio_bytes = None
        if response.candidates and response.candidates[0].content.parts:
            for part in response.candidates[0].content.parts:
                # Part could have inline_data
                if hasattr(part, "inline_data") and part.inline_data:
                    audio_bytes = part.inline_data.data
                    break
                # Or standard dict-like access
                elif isinstance(part, dict) and "inline_data" in part:
                    audio_bytes = part["inline_data"]["data"]
                    break
        
        if audio_bytes:
            with open(filename, "wb") as f:
                f.write(audio_bytes)
            print(f"Audio briefing successfully saved to {filename}")
            
            # Copy to latest.mp3
            shutil.copy2(filename, latest_filename)
            print(f"Copied audio to {latest_filename}")
            return filename
        else:
            print("No audio bytes returned in the AI TTS response.")
            return None
            
    except Exception as e:
        print(f"Failed to generate audio briefing via AI TTS: {e}")
        return None
