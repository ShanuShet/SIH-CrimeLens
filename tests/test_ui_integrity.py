import os
import re
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

class TestUIIntegrity(unittest.TestCase):
    def test_html_controls(self):
        html_path = os.path.join(ROOT, "app", "templates", "index.html")
        with open(html_path, "r", encoding="utf-8") as f:
            html = f.read()

        # Graph controls
        self.assertIn('id="zoomInGraphButton"', html)
        self.assertIn('id="zoomOutGraphButton"', html)
        self.assertIn('id="fitGraphButton"', html)
        self.assertIn('id="resetGraphButton"', html)

        # Delete Case Modal
        self.assertIn('id="deleteCaseModal"', html)
        self.assertIn('id="deleteCaseModalTitle"', html)
        self.assertIn('id="deleteCaseModalRef"', html)
        self.assertIn('id="cancelDeleteCaseButton"', html)
        self.assertIn('id="confirmDeleteCaseButton"', html)
        self.assertIn('delete-modal-warning', html)
        print("[OK] HTML controls verified")

    def test_css_styles(self):
        css_path = os.path.join(ROOT, "app", "static", "styles.css")
        with open(css_path, "r", encoding="utf-8") as f:
            css = f.read()

        # Danger & modal styles
        self.assertIn('.danger-btn', css)
        self.assertIn('.case-btn-delete', css)
        self.assertIn('.delete-modal-body', css)
        self.assertIn('.delete-modal-warning', css)
        self.assertIn('.entity-res-badge', css)
        self.assertIn('.entity-res-badge.exact', css)
        self.assertIn('.entity-res-badge.probable', css)
        self.assertIn('.entity-res-badge.ambiguous', css)
        print("[OK] CSS styles verified")

    def test_js_graph_and_layout(self):
        js_path = os.path.join(ROOT, "app", "static", "app.js")
        with open(js_path, "r", encoding="utf-8") as f:
            js = f.read()

        # COSE layout
        self.assertIsNotNone(re.search(r'name\s*:\s*["\']cose["\']', js), "COSE layout must be configured in Cytoscape")
        self.assertIn('idealEdgeLength', js)
        self.assertIn('nodeRepulsion', js)

        # Node labels & icons
        self.assertIn('data(displayLabel)', js)
        self.assertIn('entityIcon', js)

        # Node shapes
        self.assertIsNotNone(re.search(r'shape\s*:\s*["\']ellipse["\']', js))
        self.assertIsNotNone(re.search(r'shape\s*:\s*["\']diamond["\']', js))
        self.assertIsNotNone(re.search(r'shape\s*:\s*["\']rectangle["\']', js))
        self.assertIsNotNone(re.search(r'shape\s*:\s*["\']roundrectangle["\']', js))
        self.assertIsNotNone(re.search(r'shape\s*:\s*["\']hexagon["\']', js))

        # Delete case handlers
        self.assertIn('openDeleteCaseModal', js)
        self.assertIn('closeDeleteCaseModal', js)
        self.assertIn('deleteCase', js)
        self.assertIn('caseExplicitlyCleared', js)
        self.assertIn('renderResolutionHtml', js)
        print("[OK] JavaScript logic & layout verified")

if __name__ == "__main__":
    unittest.main()
