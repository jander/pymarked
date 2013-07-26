PyMarked
=========

A markdown parser and compiler, written in Python, translated from [marked](https://github.com/chjj/marked) which written in javascrpt.

usage
------

### simple example

```python
>>> from pymarked import marked

>>> print marked('I am using __markdown__.')

>>> <p>I am using <i>markdown</i>.</p>
```

### options usage example

```python
>>> src = """
    <h1>Title1</h1>
    <p>a paragraph</p>
"""

>>> print marked(src, gfm=True, langPrefix='x-')

>>> <pre>
<code class="x-python">
&gt;h1&lt;Title1<&gt;/h1&lt;
&gt;p&lt;a paragraph<&gt;/p&lt;
</code>
</pre>
```

options
-------

`def marked(text, environ=None, **options):` function parse markdown src to html.
use options to control how to parse:

- __gfm__:

  Type: `Boolean` Default `True`

  Enable [GitHub flavored markdown](https://help.github.com/articles/github-flavored-markdown).

- __breaks__:

  Type: `Boolean` Default: `False`

  Enable GFM line breaks. This option requires the gfm option to be True.

- __sanitize__:

  Type: `Boolean` Default: `False`

  Sanitize the output. Ignore any HTML that has been input.

- __smartLists__:

  Type: `Boolean` Default: `True`

  Use smarter list behavior than the original markdown.

- __langPrefix__:

  Type: `String` Default: `'lang-'`

  Set the prefix for code block classes.

- __smartypants__:

  Type: `Boolean` Default: `False`

  Use "smart" typograhic punctuation for things like quotes and dashes.

- __header_id__:

  Type: `Boolean` Default: `False`

  Enable header_id for h1~h4

- __toc__:

  Type: `Boolean` Default: `False`

  Enable toc the document. This option requires the header_id to be True.

- __wikilink__:

  Type: `Function`

  Default:

  ```
  lambda groups, environ: '<a href="{href}" class="wiki">{text}</a>'.format(
        href=groups.wikilink_name,
        text=groups.get('wikilink_text', None) or groups.wikilink_name)
  ```

  Enable parse wiki link: `[[a_wiki_page]]` or `[[a_wiki_page | wiki link text]]`.

- __macros__:

  Type: `dict`  Default: `{}`

  set block macros, see `test.MacroTestCase`

- __inline_macros__:

  Type: `dict`  Default: `{}`

  set inline macros, see `test.MacroTestCase`


License
--------

Copyright (c) 2011-2013, jander. (MIT License)
