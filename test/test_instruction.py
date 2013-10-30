import pytest
from disass.Instruction32 import is_an_operator
from disass.Instruction32 import compute_operation
from disass.Register32 import Register32


class Test_Instruction_Disass32(object):
    @pytest.mark.parametrize("operation", [
        ("3+5", "+"),
        ("2-4", "-"),
        ("2/4", "/"),
        ("2*4", "*"),
        ("2+4*2", "+"),
        ("2+4/2", "+"),
        ("2+4/2", "+"),
        ("2**4_2", None),
        ("2//4^2", None),
        ("2\4_2", None),
        ("2++4//2", None),
    ])
    def test_is_operator(self, operation):
        """
        Test de l'initialisation du moteur disass 32
        """
        r = is_an_operator(operation[0])
        if r == operation[1]:
            assert True
        else:
            print operation[0], operation[1], r
            assert False
        return

    @pytest.mark.parametrize("o", [
        ("3+5", 8), ("2-4", -2), ("2/4", 2 / 4), ("2*4", 2 * 4), ("2+4*2", 2 + 4 * 2),
        ("2+4/2", 2 + 4 / 2), ("2-4/2", 2 - 4 / 2), ("2-0/2", 2 - 0 / 2), ("0/2*3*6+2", 0 / 2 * 3 * 6 + 2)
    ])
    def test_compute_operation(self, o):
        """
        Test de l'initialisation du moteur disass 32
        """
        register = Register32()
        r = compute_operation(o[0], register)
        if r == o[1]:
            assert True
        else:
            print o[0], o[1], r
            assert False
        return

    @pytest.mark.parametrize("o", [
        ("3+5+eax", 13), ("2-4+eax", 3), ("2/4+eax", 2 / 4 + 5), ("2*4*eax", 40), ("2+eax*2", 12),
        ("0/2*3*eax+2", 2)
    ])
    def test_compute_operation_eax(self, o):
        """
        Test de l'initialisation du moteur disass 32
        """
        register = Register32()
        register.eax = 5
        r = compute_operation(o[0], register)
        if r == o[1]:
            assert True
        else:
            print o[0], o[1], r
            assert False
        return


# vim:ts=4:expandtab:sw=4
