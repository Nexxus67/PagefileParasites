import json
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from datetime import datetime
import sys

def parse_log_file(log_file):
    """Parse the JSONL log file and extract events"""
    events = []
    
    try:
        with open(log_file, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    events.append(event)
                except json.JSONDecodeError as e:
                    print(f"Warning: Invalid JSON on line {line_num}: {e}")
    except FileNotFoundError:
        print(f"Error: Log file '{log_file}' not found.")
        sys.exit(1)
    
    return events

def extract_timeline_data(events):
    """Extract timeline data for visualization"""
    timeline_data = []
    
    for event in events:
        timestamp_str = event.get('timestamp')
        event_type = event.get('event_type')
        data = event.get('data', {})
        
        if not timestamp_str or not event_type:
            continue
            
        try:
            # Parse ISO format timestamp
            timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        except ValueError:
            # Fallback for different formats
            try:
                timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%f")
            except ValueError:
                try:
                    timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S")
                except ValueError:
                    print(f"Warning: Could not parse timestamp: {timestamp_str}")
                    continue
        
        # Extract relevant data based on event type
        event_info = {
            'timestamp': timestamp,
            'event_type': event_type,
            'label': event_type.replace('_', ' ').title(),
            'details': {}
        }
        
        # Add specific details based on event type
        if event_type == 'payload_info':
            event_info['details'] = {
                'Image Base': data.get('image_base', 'N/A'),
                'Entry Point RVA': data.get('entry_point_rva', 'N/A'),
                'Size (bytes)': data.get('size_bytes', 'N/A')
            }
        elif event_type == 'section_created':
            event_info['details'] = {
                'Section Name': data.get('section_name', 'N/A'),
                'Handle': f"0x{data.get('section_handle', 0):X}",
                'Size': f"{data.get('size', 0)} bytes"
            }
        elif event_type in ['local_mapping', 'remote_mapping']:
            event_info['details'] = {
                'Base Address': f"0x{data.get('base_address', '0x0')}",
                'Size': f"{data.get('size', 0)} bytes"
            }
        elif event_type == 'process_created':
            event_info['details'] = {
                'Process ID': data.get('process_id', 'N/A'),
                'Thread ID': data.get('thread_id', 'N/A'),
                'Process Handle': f"0x{data.get('process_handle', 0):X}",
                'Thread Handle': f"0x{data.get('thread_handle', 0):X}"
            }
        elif event_type == 'remote_image_base':
            event_info['details'] = {
                'Base Address': f"0x{data.get('base_address', '0x0')}"
            }
        elif event_type == 'apc_queued':
            event_info['details'] = {
                'Target Address': f"0x{data.get('target_address', '0x0')}",
                'Thread ID': data.get('thread_id', 'N/A')
            }
        elif event_type == 'thread_resumed':
            event_info['details'] = {
                'Thread ID': data.get('thread_id', 'N/A')
            }
        
        timeline_data.append(event_info)
    
    # Sort by timestamp
    timeline_data.sort(key=lambda x: x['timestamp'])
    
    return timeline_data

def create_timeline_visualization(timeline_data, output_file='injection_timeline.png'):
    """Create a timeline visualization of the injection process"""
    if not timeline_data:
        print("No timeline data to visualize.")
        return
    
    # Set up the figure
    fig, ax = plt.subplots(figsize=(14, 8))
    
    # Define colors for different event types
    color_map = {
        'payload_info': '#1f77b4',
        'section_created': '#ff7f0e',
        'local_mapping': '#2ca02c',
        'process_created': '#d62728',
        'remote_image_base': '#9467bd',
        'remote_mapping': '#8c564b',
        'apc_queued': '#e377c2',
        'thread_resumed': '#7f7f7f'
    }
    
    # Plot each event as a point on the timeline
    y_positions = range(len(timeline_data))
    timestamps = [event['timestamp'] for event in timeline_data]
    event_types = [event['event_type'] for event in timeline_data]
    labels = [event['label'] for event in timeline_data]
    
    # Convert timestamps to numeric values for plotting
    base_time = timestamps[0]
    numeric_times = [(ts - base_time).total_seconds() for ts in timestamps]
    
    # Create scatter plot
    for i, (time_val, event_type, y_pos) in enumerate(zip(numeric_times, event_types, y_positions)):
        color = color_map.get(event_type, '#cccccc')
        ax.scatter(time_val, y_pos, s=100, c=color, alpha=0.8, edgecolors='black', linewidth=1)
        
        # Add label
        ax.annotate(labels[i], 
                   xy=(time_val, y_pos), 
                   xytext=(5, 5), 
                   textcoords='offset points',
                   fontsize=9,
                   fontweight='bold',
                   bbox=dict(boxstyle='round,pad=0.3', facecolor='yellow', alpha=0.7))
    
    # Customize the plot
    ax.set_yticks(y_positions)
    ax.set_yticklabels([f"{i+1}. {labels[i]}" for i in y_positions])
    ax.set_xlabel('Time Elapsed (seconds)')
    ax.set_title('Process Injection Timeline - Pagefile Parasites Technique')
    ax.grid(True, axis='x', linestyle='--', alpha=0.7)
    
    # Add legend
    legend_elements = [mpatches.Patch(color=color, label=event_type.replace('_', ' ').title()) 
                      for event_type, color in color_map.items() if event_type in event_types]
    ax.legend(handles=legend_elements, loc='upper right', bbox_to_anchor=(1.15, 1))
    
    # Adjust layout to prevent label cutoff
    plt.tight_layout()
    
    # Save the figure
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"Timeline visualization saved to: {output_file}")
    
    # Show the plot
    plt.show()

def create_detailed_timeline_table(timeline_data):
    """Create a detailed table view of the timeline"""
    print("\n" + "="*80)
    print("DETAILED INJECTION TIMELINE")
    print("="*80)
    
    for i, event in enumerate(timeline_data, 1):
        print(f"\n{i}. {event['label']}")
        print(f"   Time: {event['timestamp'].strftime('%H:%M:%S.%f')[:-3]}")
        print(f"   Type: {event['event_type']}")
        
        if event['details']:
            print("   Details:")
            for key, value in event['details'].items():
                print(f"     {key}: {value}")

def main():
    log_file = "injection_log.jsonl"
    
    print("Parsing injection log file...")
    events = parse_log_file(log_file)
    
    if not events:
        print("No events found in log file.")
        return
    
    print(f"Found {len(events)} events in log file.")
    
    # Extract timeline data
    timeline_data = extract_timeline_data(events)
    
    # Create detailed table view
    create_detailed_timeline_table(timeline_data)
    
    # Create visualization
    print("\nGenerating timeline visualization...")
    create_timeline_visualization(timeline_data)

if __name__ == "__main__":
    main()