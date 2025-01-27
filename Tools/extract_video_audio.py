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

def process_directory(directory: str):
    """
    Processes all MP4 files in the given directory.

    Args:
        directory (str): The path to the directory.
    """
    try:
        if not os.path.isdir(directory):
            raise NotADirectoryError(f"The path '{directory}' is not a directory.")

        # List all MP4 files in the directory
        mp4_files = [os.path.join(directory, f) for f in os.listdir(directory) if f.endswith('.mp4')]

        if not mp4_files:
            print(f"No MP4 files found in directory '{directory}'.")
            return

        for mp4_file in mp4_files:
            extract_audio_from_mp4(mp4_file)

    except Exception as e:
        print(f"An error occurred: {e}")

def main():
    parser = argparse.ArgumentParser(description="Extract audio from an MP4 file or all MP4 files in a directory and save them as MP3 files.")
    parser.add_argument('path', nargs='?', help="The path to the MP4 file or directory containing MP4 files.")
    args = parser.parse_args()

    if args.path:
        path = args.path
    else:
        path = input("Enter the path to the MP4 file or directory: ")

    if os.path.isdir(path):
        process_directory(path)
    else:
        extract_audio_from_mp4(path)

if __name__ == "__main__":
    main()