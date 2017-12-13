import z3
import random

def get_rand_ans(conds):
    ASSERT = '(assert {})'
    asserts = list(map(lambda cond: ASSERT.format(cond), conds))

    CMDS = """
    (set-option :smt.arith.random_initial_value true)
    (declare-const x Int)
    (declare-const y Int)
    {}
    (check-sat-using (using-params qflra :random_seed {}))
    (get-model)
    """
    cmds = CMDS.format(asserts, )
    
    return z3.parse_smt2_string(CMDS)

if __name__ == '__main__':
    get_rand_ans()