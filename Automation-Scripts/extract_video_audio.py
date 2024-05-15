import argparse
import os
from moviepy.editor import VideoFileClip

def extract_audio_from_mp4(mp4_file: str):
    """
    Extracts audio from an MP4 file and saves it as an MP3 file with the same name.

    Args:
        mp4_file (str): The path to the MP4 file.
    """
    try:
        # Validate the file path
        if not os.path.isfile(mp4_file):
            raise FileNotFoundError(f"The file '{mp4_file}' does not exist.")

        # Get the filename without the extension
        filename, _ = os.path.splitext(mp4_file)

        # Create a VideoFileClip object from the MP4 file
        print(f"Processing video file: {mp4_file}")
        video = VideoFileClip(mp4_file)

        # Extract the audio from the video
        audio = video.audio

        # Save the audio as an MP3 file with the same name
        audio_file = f"{filename}.mp3"
        print(f"Saving audio to: {audio_file}")
        audio.write_audiofile(audio_file)

        # Close the video and audio clips
        video.close()
        audio.close()
        print("Audio extraction completed successfully.")

    except Exception as e:
        print(f"An error occurred: {e}")

def main():
    parser = argparse.ArgumentParser(description="Extract audio from an MP4 file and save it as an MP3 file.")
    parser.add_argument('mp4_file', nargs='?', help="The path to the MP4 file.")
    args = parser.parse_args()

    if args.mp4_file:
        mp4_file = args.mp4_file
    else:
        mp4_file = input("Enter the path to the MP4 file with no quotes: ")

    extract_audio_from_mp4(mp4_file)

if __name__ == "__main__":
    main()