__author__ = 'jiang'

import unittest
from os.path import basename, join, splitext, split, dirname
import re
import glob
import logging

from pymarked import marked, defaults, pdict


class FileTestCase(unittest.TestCase):
    def __init__(self, textpath):
        super(FileTestCase, self).__init__()
        self.textpath = textpath

    def read(self, filepath):
        with open(filepath) as f:
            return f.read()

    def fix_pl(self, html):
        #fix unencoded quotes
        html = re.sub(r'''='([^\n']*?)'(?=[^<>\n]*>)''', r'=&__APOS__;\1&__APOS__;', html)
        html = re.sub(r'''="([^\n"]*?)"(?=[^<>\n]*>)''', r'=&__QUOT__;\1&__QUOT__;', html)
        html = re.sub(r'"', '&quot;', html)
        html = re.sub(r"'", '&#39;', html)
        html = re.sub(r'&__QUOT__;', '"', html)
        html = re.sub(r'&__APOS__;', "'", html)

        #  hash > and <
        html = re.sub(r'(\d+[ ]*)>([ ]*\d+)', r'\1&gt;\2', html)
        html = re.sub(r'(\d+[ ]*)<([ ]*\d+)', r'\1&lt;\2', html)

        # fix img, in pl markdown, img element has title attribute even which is ``,
        # delete blank title atrr from img element
        html = re.sub(r'''(<img[^>]+?)title=""/>''', r'\1/>', html)
        return html

    def get_options(self, filename):
        options = pdict([(k, False) if isinstance(v, bool) else (k, v) for k, v in defaults.items()])
        if filename.find('gfm') >= 0:
            options['gfm'] = True
            if filename.find('_break') > 0:
                options['breaks'] = True
        if filename.find('smartypants') > 0:
            options['smartypants'] = True
        if filename.find('smartlist') >= 0:
            options['smartLists'] = True
        return options

    def assert_mk_equals(self, textpath, htmlpath):
        filename = basename(textpath)
        output = marked(self.read(textpath), None, **self.get_options(filename))
        wanted = self.read(htmlpath)
        dir = basename(dirname(textpath))
        if dir == 'basic':
            wanted = self.fix_pl(wanted)
        output = re.sub(r'\s', '', output)
        wanted = re.sub(r'\s', '', wanted)
        logging.debug([output])
        logging.debug([wanted])
        self.assertEqual(output, wanted, 'Failed %s' % filename)

    def runTest(self):
        test_name = splitext(basename(self.textpath))[0]
        htmlpath = join(dirname(self.textpath), '%s.html' % test_name)
        self.assert_mk_equals(self.textpath, htmlpath)



def repeat_macro(body, environ, **kwargs):
    return (body+' ') * int(kwargs['count'])


def hello_macro(body, environ, **kwargs):
    return 'Hello'


class MacroTestCase(unittest.TestCase):
    def runTest(self):
        text = '''<<repeat count="2">>
            <<hello/>> tom
        <</repeat>>'''
        output = marked(text,
                        macros=dict(repeat=repeat_macro),
                        inline_macros=dict(hello=hello_macro))
        self.assertEquals(output, 'Hello tom Hello tom ')


def environ_macro(body, environ, **kwargs):
    return environ


class EnvironTestCase(unittest.TestCase):
    def runTest(self):
        text='''<<environ>>
        <</environ>>'''

        environ_value = 'ok'
        output = marked(text, environ=environ_value, macros=dict(environ=environ_macro))
        self.assertEquals(output, environ_value)


def suite():
    suite = unittest.TestSuite()

    path = join(dirname(__file__), 'tests/basic/*.text')
    tests = glob.glob(path)
    suite.addTests(FileTestCase(test) for test in tests)

    path = join(dirname(__file__), 'tests/marked/*.text')
    tests = glob.glob(path)
    suite.addTests(FileTestCase(test) for test in tests)

    path = join(dirname(__file__), 'tests/extra/*.text')
    tests = glob.glob(path)
    suite.addTests(FileTestCase(test) for test in tests)

    suite.addTests([MacroTestCase(), EnvironTestCase()])
    return suite


if __name__ == '__main__':
    level = logging.INFO
    #level = logging.DEBUG

    logging.basicConfig(
        format='%(levelname)s - %(name)s[%(lineno)d]: %(message)s',
        level=level)
    unittest.TextTestRunner().run(suite())
