---
tags:
  - resource
  - cheatsheet
  - jq
date: 2024-06-19
---

A cheatsheet resource for `jq` queries.
## Basic Commands

### Print the entire JSON
```sh
jq '.' data.json
```

### Pretty print JSON
```sh
jq '.' data.json
```

### Select a specific key
```sh
jq '.key' data.json
```

### Select nested keys
```sh
jq '.key1.key2' data.json
```

### Select multiple keys
```sh
jq '{key1, key2}' data.json
```

## Filtering and Transformation

### Filter array elements by condition
```sh
jq '.[] | select(.key == "value")' data.json
```

### Map values to a new array
```sh
jq '.[] | .key' data.json
```

### Add a new field
```sh
jq '. + {new_key: "new_value"}' data.json
```

### Remove a field
```sh
jq 'del(.key)' data.json
```

## Working with Arrays

### Iterate over array elements
```sh
jq '.[]' data.json
```

### Get array length
```sh
jq 'length' data.json
```

### Get element by index
```sh
jq '.[index]' data.json
```

### Select elements by condition
```sh
jq 'map(select(.key == "value"))' data.json
```

## Object Operations

### Convert object to array of key-value pairs
```sh
jq 'to_entries' data.json
```

### Convert array of key-value pairs to object
```sh
jq 'from_entries' data.json
```

### Extract only values from an object
```sh
jq 'to_entries | map(.value)' data.json
```

## Mathematical Operations

### Calculate sum of an array
```sh
jq 'add' data.json
```

### Calculate average of an array
```sh
jq 'add / length' data.json
```

## String Operations

### Concatenate strings
```sh
jq '"\(.key1) \(.key2)"' data.json
```

### Convert to uppercase
```sh
jq 'ascii_upcase' data.json
```

### Convert to lowercase
```sh
jq 'ascii_downcase' data.json
```

## Advanced Queries

### Find the maximum value by key
```sh
jq 'max_by(.key)' data.json
```

### Find the minimum value by key
```sh
jq 'min_by(.key)' data.json
```

### Group by a key
```sh
jq 'group_by(.key)' data.json
```

### Find field values by regex
```sh
jq 'select(.field | test("<REGEX_STRING"))' data.json
```

### Sort by a key
```sh
jq 'sort_by(.key)' data.json
```

## Example Queries

### Extract specific fields from nested objects
```sh
jq '.objects[] | {name: .name, value: .value}' data.json
```

### Compute derived values
```sh
jq '.[] | {name, profit_margin: (.sale_price - .purchase_price) / .purchase_price * 100}' data.json
```

### Combine multiple operations
```sh
jq 'to_entries | map(.value) | max_by(.profit_percentage) | {email, profit_percentage}' data.json
```

### Save output to a new file
```sh
jq '.' data.json > new_data.json
```

## Useful Functions

### `select` - filter based on condition
```sh
jq 'select(.key == "value")' data.json
```

### `map` - transform elements of an array
```sh
jq 'map(.key)' data.json
```

### `add` - sum elements of an array
```sh
jq 'add' data.json
```

### `del` - delete a key
```sh
jq 'del(.key)' data.json
```

### `length` - get length of an array
```sh
jq 'length' data.json
```

## Notes

- Wrap JQ expressions in single quotes to avoid shell interpretation.
- Use `.` to refer to the current object or array being processed.
- Combine filters and functions using the `|` (pipe) operator.
```ad-tip
This cheatsheet provides an overview of common JQ commands and functions, making it easy to look up how to perform various tasks with JSON data. Feel free to adjust or expand it based on your specific needs!
```
