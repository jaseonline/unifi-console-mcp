# Contributing

Thanks for your interest. This project drives undocumented APIs, so evidence matters more than opinion.

* **Open an issue first** for anything beyond a small fix, and say which console model and Network version you use.
* **Show the capture.** A new or changed endpoint needs a sanitised request and response (see `docs/adding-an-entity.md`).
* **Keep it safe.** Writes must go through the preview, confirm and verify flow. New entities need unit tests against
  the in-memory fake console and, if you have a console to test on, a live check that touches only throwaway objects.
* **No personal data.** Use documentation values: MACs `02:00:00:00:00:xx`, addresses from `192.0.2.0/24` or `10.x`
  examples, domains `example.home`. `tests/test_no_personal_data.py` checks MAC addresses.
* Run `uv run pytest` before opening a pull request.
