import sys, unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parents[1]/"tools"))
import verify_shader_candidate_contract as subject

class ContractTests(unittest.TestCase):
    def test_pinned_target_and_slots(self):
        self.assertEqual(subject.EXE_SHA,"68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0")
        self.assertEqual(subject.FUNCTIONS,{"pixel":(0x194D3F0,0x70),"vertex":(0x194D480,0x58)})

if __name__=="__main__": unittest.main()
