#!/usr/bin/env python3

import argparse
import enum
import io
import struct

from typing import Tuple, List, Union


class BPDT:
    HEADER_FORMAT = "<IHHHHIHHHH"
    SIGNATURE = 0x55AA
    SIZE = 512
    VERSION = 1

    class Descriptor:
        FORMAT = "<III"

        class Type(enum.Enum):
            # Source: https://github.com/platomav/MEAnalyzer/blob/16f0eb9/MEA.py#L10594
            SMIP = 0  # OEM-SMIP Partition
            RBEP = 1  # ROM Boot Extensions Partition (CSE-RBE)
            FTPR = 2  # Fault Tolerant Partition (CSE-BUP/FTPR)
            UCOD = 3  # Microcode Partition
            IBBP = 4  # IBB Partition
            S_BPDT = 5  # Secondary BPDT
            OBBP = 6  # OBB Partition
            NFTP = 7  # Non-Fault Tolerant Partition (CSE-MAIN)
            ISHC = 8  # ISH Partition
            DLMP = 9  # Debug Launch Module Partition
            UEPB = 10  # IFP Override/Bypass Partition
            UTOK = 11  # Debug Tokens Partition
            UFS_PHY = 12  # UFS PHY Partition
            UFS_GPP_LUN = 13  # UFS GPP LUN Partition
            PMCP = 14  # PMC Partition (a.k.a. PCOD)
            IUNP = 15  # IUnit Partition
            NVMC = 16  # NVM Configuration
            UEP = 17  # Unified Emulation Partition
            WCOD = 18  # CSE-WCOD Partition
            LOCL = 19  # CSE-LOCL Partition
            OEMP = 20  # OEM KM Partition
            FITC = 21  # OEM Configuration (fitc.cfg)
            PAVP = 22  # Protected Audio Video Path
            IOMP = 23  # USB Type C IO Manageability Partition (UIOM)
            xPHY = 24  # USB Type C MG Partition (a.k.a. MGPP)
            TBTP = 25  # USB Type C Thunderbolt Partition (TBT)
            PLTS = 26  # Platform Settings
            DPHY = 31  # USB Type C Dekel PHY
            PCHC = 32  # PCH Configuration
            ISIF = 33  # Intel Safety Island Firmware
            ISIC = 34  # Intel Safety Island Configuration (N/A)
            HBMI = 35  # HBM IO Partition
            OMSM = 36  # OOB MSM Partition
            GTGP = 37  # GT-GPU Partition
            MDFI = 38  # MDF IO Partition
            PUNP = 39  # PUnit Partition
            PHYP = 40  # GSC PHY Partition
            SAMF = 41  # SAM Firmware
            PPHY = 42  # PPHY Partition
            GBST = 43  # GBST Partition
            TCCP = 44  # USB Type C Controller Partition (a.k.a. TPCC)
            PSEP = 45  # Programmable Services Engine Partition

        def __init__(self, d_type: Union[int, str], d_start: int, d_size: int = None, d_end: int = None, bpdt_offset=0):
            if d_size is None and d_end is None:
                raise ValueError("Must provide one of d_size, d_end")
            self.type: BPDT.Descriptor.Type = getattr(self.Type, {
                int: "__call__",
                str: "__getitem__",
            }[type(d_type)])(d_type)
            self.start = d_start + bpdt_offset
            self.size = d_end - d_start if d_size is None else d_size

        @property
        def end(self):
            return self.start + self.size

        @classmethod
        def unpack_from(cls, buffer: bytes, offset=0, bpdt_offset=0):
            return cls(*struct.unpack_from(cls.FORMAT, buffer, offset), bpdt_offset=bpdt_offset)

        def pack_into(self, buffer: bytearray, offset=0, bpdt_offset=0):
            struct.pack_into(self.FORMAT, buffer, offset, *(
                self.type.value,
                self.start - bpdt_offset,
                self.size,
            ))

        def __repr__(self):
            return f"Descriptor(type={self.type.__repr__()}, start={self.start}, size={self.size})"

    def __init__(
        self,
        offset: int,
        reserved: int,
        checksum: int,
        ifwi_version: int,
        fit_version: Tuple[int, int, int, int],
        descriptors: List[Descriptor],
        bpdt_offset=None,
        first_id=0,
    ):
        self.offset = offset
        self.reserved = reserved
        self._checksum = checksum
        self.ifwi_version = ifwi_version
        self.fit_version = fit_version
        self.descriptors = descriptors
        self.bpdt_offset = bpdt_offset
        self.first_id = first_id

    @property
    def checksum(self):
        # TODO: Actually calculate this
        return self._checksum

    @classmethod
    def unpack_from(cls, buffer: bytes, offset=0, real_offset=None, bpdt_offset=None, **kwargs):
        if real_offset is None:
            real_offset = offset

        header_tuple = struct.unpack_from(cls.HEADER_FORMAT, buffer, offset)
        signature, descriptor_count, bpdt_version, reserved, checksum, ifwi_version = header_tuple[:6]
        fit_version = header_tuple[6:]

        assert signature == 0x55aa, f"Invalid BPDT header signature {signature}"
        assert bpdt_version == cls.VERSION, f"Unknown BPDT version {bpdt_version}"

        header_size = struct.calcsize(cls.HEADER_FORMAT)
        descriptor_size = struct.calcsize(cls.Descriptor.FORMAT)
        d_bpdt_offset = real_offset if bpdt_offset is None else bpdt_offset

        descriptors = []
        for i in range(descriptor_count):
            d_offset = offset + header_size + i * descriptor_size
            descriptor = cls.Descriptor.unpack_from(buffer, d_offset, d_bpdt_offset)
            descriptors.append(descriptor)

        return cls(
            offset=real_offset,
            reserved=reserved,
            checksum=checksum,
            ifwi_version=ifwi_version,
            fit_version=fit_version,
            descriptors=descriptors,
            bpdt_offset=bpdt_offset,
            **kwargs,
        )

    def pack_into(self, buffer: bytearray, offset=0):
        struct.pack_into(self.HEADER_FORMAT, buffer, offset, *(
            self.SIGNATURE,
            len(self.descriptors),
            self.VERSION,
            self.reserved,
            self.checksum,
            self.ifwi_version,
            *self.fit_version,
        ))

        header_size = struct.calcsize(self.HEADER_FORMAT)
        descriptor_size = struct.calcsize(self.Descriptor.FORMAT)
        d_bpdt_offset = self.offset if self.bpdt_offset is None else self.bpdt_offset

        for i, d in enumerate(self.descriptors):
            d_offset = offset + header_size + i * descriptor_size
            d.pack_into(buffer, d_offset, d_bpdt_offset)

    def __str__(self):
        name = "BPDT" if self.bpdt_offset is None else "S-BPDT"
        return "\n".join([
            f"{name:6} @ 0x{self.offset:X}  (FIT v{'.'.join(map(str, self.fit_version))})",
            "  # Type            Start     Size      End",
            *[
                f" {self.first_id + i:2} {d.type.name:12}"
                f" {d.start:8X} {d.size:8X} {d.end:8X}"
                for i, d in enumerate(self.descriptors)
            ],
        ])


class IFWI:
    BPDT_OFFSETS = [0x100000, 0x800000]

    def __init__(self, spi_file: io.BufferedRandom):
        self.bpdts = []
        self.spi_file = spi_file

        for b_offset in self.BPDT_OFFSETS:
            spi_file.seek(b_offset)
            b_bytes = spi_file.read(BPDT.SIZE)
            b_first_id = self.bpdts[-1].first_id + len(self.bpdts[-1].descriptors) if self.bpdts else 0
            b = BPDT.unpack_from(b_bytes, real_offset=b_offset, first_id=b_first_id)
            self.bpdts.append(b)

            b_bytearray = bytearray(b'\xFF' * BPDT.SIZE)
            b.pack_into(b_bytearray)
            assert bytes(b_bytearray) == b_bytes, "BPDT self-check failed"

            for d in b.descriptors:
                if d.type != BPDT.Descriptor.Type.S_BPDT:
                    continue
                spi_file.seek(d.start)
                s_bytes = spi_file.read(BPDT.SIZE)
                s_first_id = b.first_id + len(b.descriptors)
                s = BPDT.unpack_from(s_bytes, real_offset=d.start, bpdt_offset=b_offset, first_id=s_first_id)
                self.bpdts.append(s)

                s_bytearray = bytearray(b'\xFF' * BPDT.SIZE)
                s.pack_into(s_bytearray)
                assert bytes(s_bytearray) == s_bytes, "S-BPDT self-check failed"

    def commit_bpdts(self):
        for b in self.bpdts:
            b_bytearray = bytearray(b'\xFF' * BPDT.SIZE)
            b.pack_into(b_bytearray)
            self.spi_file.seek(b.offset)
            self.spi_file.write(b_bytearray)

    def __getitem__(self, item) -> BPDT.Descriptor:
        i = 0
        while item - self.bpdts[i].first_id >= len(self.bpdts[i].descriptors):
            i += 1
        return self.bpdts[i].descriptors[item - self.bpdts[i].first_id]

    def __str__(self):
        return "\n\n".join([str(bpdt) for bpdt in self.bpdts])


def print_main(ifwi: IFWI, args: argparse.Namespace):
    print(ifwi)


def add_main(ifwi: IFWI, args: argparse.Namespace):
    raise NotImplementedError("The 'add' command has not been implemented yet.")


def move(ifwi: IFWI, d_move: BPDT.Descriptor, start: int = None, size: int = None, end: int = None, level=0):
    if start is None:
        start = d_move.start

    if size is None:
        if end is None:
            size = d_move.size
        else:
            size = end - start

    prefix = f"{level * '-'}Moving/resizing {d_move.type.name}"
    print(f"{prefix:28} from {d_move.start:8X} + {d_move.size:8X} to {start:8X} + {size:8X}...")

    if start < d_move.start:
        # TODO: Double-check function logic for invalidated assumptions if/when implementing.
        raise NotImplementedError("Moving a partition backwards has not been implemented yet.")

    if d_move.type == BPDT.Descriptor.Type.S_BPDT and size < d_move.size:
        # TODO: Double-check function logic for invalidated assumptions if/when implementing.
        raise NotImplementedError("Shrinking an S-BPDT partition has not been implemented yet.")

    if size == 0:
        # Nothing extra to do when the end result is an empty partition.
        pass
    elif size <= d_move.size and 0 <= start - d_move.start <= d_move.size - size:
        # Nothing extra to do when staying within the original bounds.
        pass
    else:
        s_bpdt_contents = []

        # Recursively push conflicting partitions out of the way.
        for d in ifwi:
            if d == d_move:
                continue

            if d.size == 0:
                # Ignore empty partitions when looking for conflicts.
                continue

            if d.type == BPDT.Descriptor.Type.S_BPDT and d.start <= d_move.start and d_move.end <= d.end < start + size:
                # `d` contains `d_move`, and needs to be extended.
                move(ifwi, d, d.start, end=start + size, level=level + 1)
            elif d_move.end <= d.start < start + size and start < d.end:
                # `d` comes after `d_move`, and needs to be moved.
                move(ifwi, d, start + size, level=level + 1)
            elif d_move.type == BPDT.Descriptor.Type.S_BPDT and d_move.start <= d.start and d.end <= d_move.end:
                # `d_move` contains `d`. Shift `d` without moving data.
                # `d`'s data will be moved with the entire S-BPDT later.
                print(f"{(level + 1) * '-'}Shifting {d.type.name}...")
                d.start = d.start + start - d_move.start

    # Read the partition from the current location.
    ifwi.spi_file.seek(d_move.start)
    d_part = ifwi.spi_file.read(d_move.size)

    # Update the descriptor in the BPDT with the new start/size.
    d_move.start = start
    d_move.size = size
    ifwi.commit_bpdts()

    # Write the partition to the new location, truncating if necessary.
    ifwi.spi_file.seek(d_move.start)
    ifwi.spi_file.write(d_part[:d_move.size])


def move_main(ifwi: IFWI, args: argparse.Namespace):
    d = ifwi[args.NUMBER]
    move(ifwi, d, start=args.start, size=args.size, end=args.end)


def delete_main(ifwi: IFWI, args: argparse.Namespace):
    raise NotImplementedError("The 'delete' command has not been implemented yet.")


def extract_main(ifwi: IFWI, args: argparse.Namespace):
    d = ifwi[args.NUMBER]
    ifwi.spi_file.seek(d.start)
    p = ifwi.spi_file.read(d.size)
    args.TO.write(p)


def update_main(ifwi: IFWI, args: argparse.Namespace):
    d = ifwi[args.NUMBER]
    p = args.FROM.read()
    if d.size != len(p):
        move(ifwi, d, size=len(p))
    ifwi.spi_file.seek(d.start)
    ifwi.spi_file.write(p)


def parse_args():
    def auto_int(x):
        return int(x, 0)

    parser = argparse.ArgumentParser(
        description='Manipulate partitions in an Intel IFWI SPI image.',
    )

    parser.add_argument('INPUT', type=argparse.FileType('rb+'), help="the SPI image to manipulate")
    parser.add_argument('-o', '--output', type=argparse.FileType('wb'),
                        help="write modified SPI image to OUTPUT instead of modifying INPUT")

    subparsers = parser.add_subparsers(metavar='COMMAND', required=True)

    parser_print = subparsers.add_parser('print', help='print the partition table')
    parser_print.set_defaults(command=print_main)

    parser_add = subparsers.add_parser('add', help='add a new partition', epilog="\n".join([
        "supported TYPEs:",
        *(f"  {t.name}" for t in BPDT.Descriptor.Type)
    ]), formatter_class=argparse.RawDescriptionHelpFormatter)
    parser_add.set_defaults(command=add_main)
    type_choices = [t.name for t in BPDT.Descriptor.Type]
    parser_add.add_argument('-t', '--type', metavar='TYPE', required=True, choices=type_choices)
    parser_add.add_argument('--start', type=auto_int, required=True)
    parser_add_size = parser_add.add_mutually_exclusive_group(required=True)
    parser_add_size.add_argument('--size', type=auto_int)
    parser_add_size.add_argument('--end', type=auto_int)

    parser_move = subparsers.add_parser('move', help='move/resize a partition')
    parser_move.set_defaults(command=move_main)
    parser_move.add_argument('NUMBER', type=auto_int)
    parser_move.add_argument('--start', type=auto_int)
    parser_move_size = parser_move.add_mutually_exclusive_group()
    parser_move_size.add_argument('--size', type=auto_int)
    parser_move_size.add_argument('--end', type=auto_int)

    parser_delete = subparsers.add_parser('delete', help='remove a partition')
    parser_delete.set_defaults(command=delete_main)
    parser_delete.add_argument('NUMBER', type=auto_int)

    parser_extract = subparsers.add_parser('extract', help='extract a partition')
    parser_extract.set_defaults(command=extract_main)
    parser_extract.add_argument('NUMBER', type=auto_int)
    parser_extract.add_argument('TO', type=argparse.FileType('wb'))

    parser_update = subparsers.add_parser('update', help='update a partition')
    parser_update.set_defaults(command=update_main)
    parser_update.add_argument('NUMBER', type=auto_int)
    parser_update.add_argument('FROM', type=argparse.FileType('rb'))

    return parser.parse_args()


def main():
    args = parse_args()
    if args.output:
        raise NotImplementedError("The '--output' flag has not been implemented yet.")
    ifwi = IFWI(args.INPUT)
    args.command(ifwi, args)


if __name__ == "__main__":
    main()
