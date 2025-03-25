#!/usr/bin/env python3

import sys
import json
import argparse
from swsscommon import swsscommon

def usage():
    print("Usage: swssconfig.py [--bulk-size SIZE] [FILE...]")
    print("       (default config folder is /etc/swss/config.d/)")
    print("       (default bulk size is 1000)")

def write_config_to_db(data, bulk_size):
    # Connect to APPL_DB
    db = swsscommon.DBConnector("APPL_DB", 0, False)
    pipeline = swsscommon.RedisPipeline(db)
    
    # Keep track of tables to avoid creating duplicates
    tables = {}
    entry_count = 0

    try:
        for item in data:
            if len(item) != 2:  # Must have exactly 2 elements (key and op)
                print(f"Error: Invalid item format - {item}", file=sys.stderr)
                return False

            key = None
            op = None
            fields = None

            for k, v in item.items():
                if k == "OP":
                    op = v
                else:
                    key = k
                    fields = v

            if not key or not op:
                print(f"Error: Missing key or operation - {item}", file=sys.stderr)
                return False

            # Split key into table name and key
            try:
                table_name, key_name = key.split(":", 1)
            except ValueError:
                print(f"Error: Invalid key format '{key}' - must contain ':'", file=sys.stderr)
                return False

            # Get or create ProducerStateTable
            if table_name not in tables:
                tables[table_name] = swsscommon.ProducerStateTable(pipeline, table_name, True)

            # Convert fields to list of tuples
            if not isinstance(fields, dict):
                print(f"Error: Fields must be a dictionary - {fields}", file=sys.stderr)
                return False

            field_values = [(str(k), str(v)) for k, v in fields.items()]

            # Perform operation
            if op.lower() == "set":
                tables[table_name].set(key_name, field_values)
            elif op.lower() == "del":
                tables[table_name]._del(key_name)
            else:
                print(f"Error: Invalid operation '{op}'", file=sys.stderr)
                return False

            entry_count += 1
            
            # Flush pipeline every bulk_size entries
            if entry_count % bulk_size == 0:
                print(f"Flushing pipeline after {entry_count} entries...")
                pipeline.flush()

        # Final flush for any remaining entries
        if entry_count % bulk_size != 0:
            print(f"Flushing pipeline for final {entry_count % bulk_size} entries...")
            pipeline.flush()

        print(f"Total entries processed: {entry_count}")
        return True

    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        return False

def main():
    parser = argparse.ArgumentParser(description='Configure SWSS through JSON file')
    parser.add_argument('--bulk-size', type=int, default=1000,
                      help='Number of entries to process before flushing (default: 1000)')
    parser.add_argument('files', nargs='*', help='JSON configuration files')
    args = parser.parse_args()

    if not args.files:
        usage()
        return 1

    success = True
    for config_file in args.files:
        try:
            print(f"Loading config from {config_file}")
            with open(config_file) as f:
                data = json.load(f)
                
            if not isinstance(data, list):
                print(f"Error: Root element in {config_file} must be an array", file=sys.stderr)
                success = False
                continue

            if not write_config_to_db(data, args.bulk_size):
                print(f"Error: Failed to apply configuration from {config_file}", file=sys.stderr)
                success = False
            else:
                print(f"Successfully applied configuration from {config_file}")

        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in {config_file}: {str(e)}", file=sys.stderr)
            success = False
        except FileNotFoundError:
            print(f"Error: File not found: {config_file}", file=sys.stderr)
            success = False
        except Exception as e:
            print(f"Error processing {config_file}: {str(e)}", file=sys.stderr)
            success = False

    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())