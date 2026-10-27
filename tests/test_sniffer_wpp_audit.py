import unittest
import io
import json
from pathlib import Path
import tempfile
import sys
from iara.sniffer.wpp_audit import summarize
from iara.sniffer.wpp_audit import read_jsonl


def row(i=0, **kw):
    return dict(dict(index=i, opcode=0, direction='client', status='Success', remaining=0), **kw)


class Reserved(unittest.TestCase):
    def invalid(self, value, expected=1, code='invalid_audit_row'):
        with self.assertRaises(ValueError) as ctx:
            summarize(value, expected)
        self.assertEqual(str(ctx.exception), code)

    def test_expected_boundary_and_types(self):
        for v in (-1, 1000001, True, False, None, 'SECRET', 1.0):
            self.invalid([], v, 'invalid_expected_records')
        self.assertFalse(summarize([], 1000000)['complete'])
        self.assertTrue(summarize([], 0)['complete'])

    def test_all_statuses_and_exact_keys(self):
        statuses=('Success', 'WithErrors', 'NotParsed', 'NoStructure', 'None')
        result=summarize((row(i,status=s,remaining=int(i>0)) for i,s in enumerate(statuses)),5)
        self.assertEqual(set(result), {'expected','observed','complete','counts','remaining_bytes','opcodes'})
        self.assertEqual(result['counts'], dict.fromkeys(statuses,1))
        self.assertEqual(result['remaining_bytes'],4)
        self.assertTrue(result['complete'])  # coverage is not semantic success
        self.assertEqual(set(result['opcodes'][0]), {'direction','opcode','counts','remaining_bytes'})

    def test_reject_input_types_and_extra_content(self):
        for bad in (None, 2, 'SECRET', [None], ['SECRET'], [[]], [row(private='SECRET')]):
            self.invalid(bad)
        bad=row();del bad['remaining'];self.invalid([bad])

    def test_bad_field_values(self):
        fields={'index':(-1,1,True,0.0,'SECRET'), 'opcode':(-1,2**32,False,1.0,[]),
                'direction':('', 'Client', 'SECRET', 0,[]),
                'status':('', None, 'success', [], True),
                'remaining':(-1,16777217,True,'SECRET',0.0)}
        for name, values in fields.items():
            for value in values:
                with self.subTest(field=name,value_type=type(value).__name__):
                    self.invalid([dict(row(),**{name:value})])

    def test_duplicate_global(self):
        self.invalid([row(0),row(0,opcode=2,direction='server')],2)

    def test_one_pass_reused_mutable_row(self):
        # A streaming reader may reuse a dictionary. Do not retain it.
        def gen():
            r=row()
            for i in range(9999,-1,-1):
                r['index']=i;r['opcode']=i%100;yield r
        result=summarize(gen(),10000)
        self.assertTrue(result['complete']);self.assertEqual(result['observed'],10000)
        self.assertEqual(result['counts']['Success'],10000)
        self.assertTrue(all(g['counts']['Success']==100 for g in result['opcodes']))

    def test_sort_and_separate_direction(self):
        r=summarize([row(0,opcode=2,direction='server'), row(1,opcode=2),row(2,opcode=1)],3)
        self.assertEqual([(g['direction'],g['opcode']) for g in r['opcodes']],
                         [('client',1),('client',2),('server',2)])

    def test_group_limit(self):
        self.assertEqual(len(summarize((row(i,opcode=i) for i in range(4096)),4096)['opcodes']),4096)
        self.invalid((row(i,opcode=i) for i in range(4097)),4097,'opcode_limit')

    def test_bounds_and_missing_rows(self):
        r=summarize([row(999999,opcode=2**32-1,status='WithErrors',remaining=16777216)],1000000)
        self.assertFalse(r['complete']);self.assertEqual(r['remaining_bytes'],16777216)
        self.invalid([row()],0)
        self.invalid([row(remaining=1)])

    def test_independent_calls(self):
        first=summarize([row()],1);first['counts']['Success']=700
        first['opcodes'][0]['counts']['Success']=800
        self.assertEqual(summarize([row()],1)['counts']['Success'],1)


class AdapterTests(unittest.TestCase):
    def stream(self,rows):
        return io.BytesIO(b''.join(json.dumps(r).encode()+b'\n' for r in rows))

    def test_jsonl_and_invalid_json(self):
        self.assertTrue(read_jsonl(self.stream([row()]),1)['complete'])
        for raw in (b'{PRIVATE', b'\xff', b'\n', b'[]', b'{}', b'{"index":0,"index":1}'):
            with self.assertRaisesRegex(ValueError,'^invalid_audit_row$'):
                read_jsonl(io.BytesIO(raw),1)

    def test_duplicate_valid_key_is_not_silently_overwritten(self):
        raw=json.dumps(row()).encode().replace(b'"index": 0',b'"index": 999, "index": 0')
        with self.assertRaisesRegex(ValueError,'invalid_audit_row'):read_jsonl(io.BytesIO(raw),1)

    def test_line_bound_and_premature_eof(self):
        with self.assertRaisesRegex(ValueError,'audit_size_limit'):read_jsonl(io.BytesIO(b' '*1025),1)
        self.assertFalse(read_jsonl(self.stream([row()]),2)['complete'])
        self.assertTrue(read_jsonl(io.BytesIO(),0)['complete'])





if __name__=='__main__':unittest.main()
