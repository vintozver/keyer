import typing
import functools

def bits_to_value(bool_array: typing.Iterable[bool]) -> int:
    return functools.reduce(
        lambda x, y: (x << 1) + y,
        map(
            int,
            bool_array
        )
    )

def access_bits_to_seq(
        C10: bool, C20: bool, C30: bool,  # data block 0
        C11: bool, C21: bool, C31: bool,  # data block 1
        C12: bool, C22: bool, C32: bool,  # data block 2
        C13: bool, C23: bool, C33: bool,  # sector trailer
        ) -> typing.Annotated[bytes, 3]:
    return bytes((
        bits_to_value((not C23, not C22, not C21, not C20, not C13, not C12, not C11, not C10)),
        bits_to_value((    C13,     C12,     C11,     C10, not C33, not C32, not C31, not C30)),
        bits_to_value((    C33,     C32,     C31,     C30,     C23,     C22,     C21,     C20)),
    ))

