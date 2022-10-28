# BPDTool

```
usage: BPDTool.py [-h] [-o OUTPUT] INPUT COMMAND ...

Manipulate partitions in an Intel IFWI SPI image.

positional arguments:
  INPUT                 the SPI image to manipulate
  COMMAND
    print               print the partition table
    move                move/resize a partition
    extract             extract a partition
    update              update a partition

optional arguments:
  -h, --help            show this help message and exit
```

## Print

```
usage: BPDTool.py INPUT print [-h]

optional arguments:
  -h, --help  show this help message and exit
```

# Move

```
usage: BPDTool.py INPUT move [-h] [--start START] [--size SIZE | --end END] NUMBER

positional arguments:
  NUMBER

optional arguments:
  -h, --help     show this help message and exit
  --start START
  --size SIZE
  --end END
```

# Extract

```
usage: BPDTool.py INPUT extract [-h] NUMBER TO

positional arguments:
  NUMBER
  TO

optional arguments:
  -h, --help  show this help message and exit
```

# Update

```
usage: BPDTool.py INPUT update [-h] NUMBER FROM

positional arguments:
  NUMBER
  FROM

optional arguments:
  -h, --help  show this help message and exit
```
