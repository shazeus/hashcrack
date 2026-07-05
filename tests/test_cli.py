import json

from click.testing import CliRunner

from hashcrack.cli import cli


def test_batch_json_output_is_clean(tmp_path):
    input_file = tmp_path / "hashes.txt"
    input_file.write_text("5d41402abc4b2a76b9719d911017c592\n")

    runner = CliRunner()
    result = runner.invoke(cli, ["batch", str(input_file), "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload == [
        {
            "hash": "5d41402abc4b2a76b9719d911017c592",
            "types": ["MD5", "NTLM", "LM Hash", "Base64"],
            "found": False,
            "plaintext": None,
            "source": None,
        }
    ]


def test_batch_json_output_stays_clean_when_writing_file(tmp_path):
    input_file = tmp_path / "hashes.txt"
    output_file = tmp_path / "results.json"
    input_file.write_text("5d41402abc4b2a76b9719d911017c592\n")

    runner = CliRunner()
    result = runner.invoke(cli, ["batch", str(input_file), "--json", "--output", str(output_file)])

    assert result.exit_code == 0
    assert json.loads(result.output) == json.loads(output_file.read_text())
