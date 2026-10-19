import sys, tempfile, unittest
from pathlib import Path
from unittest import mock
sys.path.insert(0,str(Path(__file__).parents[1]/"tools"))
import workstation_variable_native_edits as subject
from workstation_fastfiles import parse_image_data_url

class VariableNativeEditsTests(unittest.TestCase):
    def test_image_data_url_mip_override_and_default(self):
        import base64
        png=b"\x89PNG\r\n\x1a\nfixture"
        encoded=base64.b64encode(png).decode()
        self.assertEqual(parse_image_data_url(f"data:image/png;base64,{encoded}",3),(png,3))
        self.assertEqual(parse_image_data_url(f"data:image/png;mips=5;base64,{encoded}",3),(png,5))
        with self.assertRaises(ValueError): parse_image_data_url(f"data:image/png;mips=0;base64,{encoded}",3)
    def test_rejects_unsupported_variable_family(self):
        with tempfile.TemporaryDirectory() as folder:
            body=Path(folder)/"body"; body.write_bytes(b"body")
            with self.assertRaisesRegex(ValueError,"unsupported family"):
                subject.apply_variable_native_edits(b"body",[{"kind":"mesh"}],
                    body_path=body,journal_path=body,trace_path=body,manifest_path=body,replay_executable=body)

    @mock.patch.object(subject,"resize_resident_images")
    def test_normalizes_image_writer_receipt(self, resize):
        resize.return_value=(b"grown",{"stream_reservation_sizes":[1,9],"proof":True})
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/"body"; path.write_bytes(b"body")
            output,receipt=subject.apply_variable_native_edits(b"body",[{"kind":"image","asset_row":{},"trace_asset":{},"width":2,"height":2,"mip_count":1,"payload":b"x"}],body_path=path,journal_path=path,trace_path=path,manifest_path=path,replay_executable=path)
        self.assertEqual(output,b"grown"); self.assertEqual(receipt["family"],"image")
        self.assertFalse(receipt["publication_ready"]); self.assertEqual(receipt["stream_reservation_sizes"],[1,9])

    @mock.patch.object(subject,"read_resident_image")
    @mock.patch.object(subject,"resize_resident_images")
    @mock.patch.object(subject,"replace_inline_shaders_with_relocation")
    @mock.patch.object(subject,"build_inventory")
    def test_combines_original_offsets_once(self, inventory, shaders, images, read_image):
        body=bytes((i%251 for i in range(1300))); inventory.return_value={"inventory_sha256":"a","shader_count":1,"journal_sha256":"b","trace_sha256":"c","manifest_sha256":"d"}
        shader_body=body[:300]+b"0123456789"+body[300:750]+body[754:]
        shaders.return_value=(shader_body,{"relocation":{"stream_reservation_sizes":[0,5,0,0,0,20],"edits":[
            {"child_archive_offset":300,"old_child_bytes":1,"physical_extent_delta":10},
            {"child_archive_offset":750,"old_child_bytes":4,"physical_extent_delta":-4}]}})
        image_body=body
        images.return_value=(bytes(image_body),{"stream_reservation_sizes":[0,12,0,0,0,10]})
        read_image.side_effect=[
            {"root_archive_offset":40,"root_bytes":bytes(232),"payload_archive_offset":280,"total_size":2},
            {"root_archive_offset":400,"root_bytes":bytes(232),"payload_archive_offset":650,"total_size":5},
            {"root_archive_offset":800,"root_bytes":bytes(232),"payload_archive_offset":1100,"total_size":3}]
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/"body"; path.write_bytes(body)
            output,receipt=subject.apply_variable_native_edits(body,[
                {"kind":"shader","asset_row":{},"trace_asset":{},"payload":b"shader"},
                {"kind":"image","asset_row":{"i":1},"trace_asset":{},"width":2,"height":2,"mip_count":1,"payload":b"AAAAAAA"},
                {"kind":"image","asset_row":{"i":2},"trace_asset":{},"width":3,"height":3,"mip_count":2,"payload":b"BB"},
                {"kind":"image","asset_row":{"i":3},"trace_asset":{},"width":4,"height":4,"mip_count":3,"payload":b"CCCCC"}],
                body_path=path,journal_path=path,trace_path=path,manifest_path=path,replay_executable=path)
        self.assertEqual(receipt["family"],"combined")
        self.assertEqual(output[280:287],b"AAAAAAA")
        self.assertEqual(output[665:667],b"BB")
        self.assertEqual(output[1108:1113],b"CCCCC")
        self.assertEqual(output[40+0x24:40+0x28],b"\x02\x00\x02\x00")
        self.assertEqual(output[415+0x24:415+0x28],b"\x03\x00\x03\x00")
        self.assertEqual(output[808+0x24:808+0x28],b"\x04\x00\x04\x00")
        self.assertTrue(receipt["writer"]["original_trace_offsets_applied_once"])

    def test_combined_spans_allow_touching_boundary_and_reject_one_byte_overlap(self):
        body=bytes((i%251 for i in range(800)))
        inventory={"inventory_sha256":"a","shader_count":1,"journal_sha256":"b",
                   "trace_sha256":"c","manifest_sha256":"d"}
        shader_writer={"relocation":{"stream_reservation_sizes":[0,0,0,0,0,20],
                       "edits":[{"child_archive_offset":400,"old_child_bytes":10,
                                  "physical_extent_delta":4}]}}
        image_writer={"stream_reservation_sizes":[0,12,0,0,0,0]}
        edits=[{"kind":"shader","asset_row":{},"trace_asset":{},"payload":b"shader"},
               {"kind":"image","asset_row":{},"trace_asset":{},"width":2,
                "height":2,"mip_count":1,"payload":b"pixels"}]
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/"body"; path.write_bytes(body)
            with mock.patch.object(subject,"build_inventory",return_value=inventory), \
                 mock.patch.object(subject,"replace_inline_shaders_with_relocation",
                                   return_value=(body[:400]+b"grow"+body[400:],shader_writer)), \
                 mock.patch.object(subject,"resize_resident_images",
                                   return_value=(body,image_writer)), \
                 mock.patch.object(subject,"read_resident_image",return_value={
                                   "root_archive_offset":40,"root_bytes":bytes(232),
                                   "payload_archive_offset":390,"total_size":10}):
                output,_=subject.apply_variable_native_edits(body,edits,body_path=path,
                    journal_path=path,trace_path=path,manifest_path=path,replay_executable=path)
                self.assertEqual(output[390:396],b"pixels")
            with mock.patch.object(subject,"build_inventory",return_value=inventory), \
                 mock.patch.object(subject,"replace_inline_shaders_with_relocation",
                                   return_value=(body[:400]+b"grow"+body[400:],shader_writer)), \
                 mock.patch.object(subject,"resize_resident_images",
                                   return_value=(body,image_writer)), \
                 mock.patch.object(subject,"read_resident_image",return_value={
                                   "root_archive_offset":40,"root_bytes":bytes(232),
                                   "payload_archive_offset":391,"total_size":10}):
                with self.assertRaisesRegex(ValueError,"original physical spans overlap"):
                    subject.apply_variable_native_edits(body,edits,body_path=path,
                        journal_path=path,trace_path=path,manifest_path=path,
                        replay_executable=path)

if __name__=="__main__": unittest.main()
