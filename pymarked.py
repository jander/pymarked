#coding=utf-8

from collections import OrderedDict
import re
import logging


class pdict(dict):
    """A dict that allows for object-like property access syntax."""

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)

    def __setattr__(self, name, value):
        self[name] = value


class BlockRule(object):
    #------------------
    #   common patterns
    #------------------
    bullet = r'(?:[*+-]|\d+\.)'

    htmltag = (r'(?!(?:'
               r'a|em|strong|small|s|cite|q|dfn|abbr|data|time|code'
               r'|var|samp|kbd|sub|sup|i|b|u|mark|ruby|rt|rp|bdi|bdo'
               r'|span|br|wbr|ins|del|img)\b)\w+(?!:/|@)\b')

    listitem = r'^([ ]*)({bull})[ ][^\n]*(?:\n(?!\1{bull} )[^\n]*)*'.format(bull=bullet)

    #------------------
    #   normal patterns
    #------------------
    normal = OrderedDict()

    normal['macro'] = r'''
        (?P<macro>
            <<
                (?P<macro_name>\S+)
                (?P<macro_attrs>
                    (?:[ ]+\S+="\S+"[ ]*)*
                )
            >>
                \s*
                (?P<macro_body>[\s\S]+?)
                \s*
            <</(?P=macro_name)>>
        )
    '''

    normal['newline'] = r'''(?P<newline>\n+)'''

    normal['code'] = r'''(?P<code>(?:[ ]{4}[^\n]+\n*)+)'''

    normal['fences'] = None

    normal['hr'] = r'''
        (?P<hr>
            [ ]{0,3}
            (?:[-*_][ ]?){3,}[ ]*
            (?:\n+|$)
        )
    '''

    normal['heading'] = r'''
        (?P<heading>
            [ ]*(?P<heading_depth>\#{1,6})[ ]*
            (?P<heading_text>[^\n]+?)
            [ #]*
            (?:\n+|$)
        )
    '''

    normal['nptable'] = None

    normal['lheading'] = r'''
        (?P<lheading>
            (?P<lheading_text>[^\n]+)
            \n
            [ ]*(?P<lheading_depth>=|-){3,}
            [ ]*\n*
        )
    '''

    normal['blockquote'] = r'''
        (?P<blockquote>
            (?:[ ]*>[^\n]+(?:\n[^\n]+)*\n*)+?
        )
    '''

    normal['list'] = r'''
        (?P<list>
            (?P<list_blank>[ ]{{0,3}})
            (?P<list_bull>{bull})[ ]
            [\s\S]+?
            (?:
              {hr} | \n{{2,}} (?![ ]) (?!(?P=list_blank){bull}[ ])\n* | \s*$
            )
        )
    '''.format(
        hr=r'\n+(?=[ ]{0,3}(?:[-*_][ ]?){3,}[ ]*(?:\n+|$))',
        bull=bullet
    )

    normal['html'] = r'''
        (?P<html>
            [ ]*
            (?:{comment}|{closed}|{closing})
            [ ]*
            (?:\n{{2,}}|\s*$)
        )
    '''.format(
        comment=r'<!--[\s\S]*?-->',
        closed=r'<(?P<html_tag>%s)[\s\S]+?<\/(?P=html_tag)>' % htmltag,
        closing=r'''<%s(?:"[^"]*"|'[^']*'|[^'">])*?>''' % htmltag
    )

    normal['def'] = r'''
        (?P<def>
            [ ]*
            \[(?P<def_key>[^\]]+)\]:[ ]*
            <?(?P<def_href>[^\s>]+)>?
            (?:
                [ ]+
                ["\(](?P<def_title>[^\n]+)["\)]
            )?
            [ ]*(?:\n|$)
        )
    '''

    normal['table'] = None

    normal['paragraph'] = r'''
        (?P<paragraph>
            (?:
                [^\n]+
                \n?
                (?!{hr}|{heading}|{lheading}|{blockquote}|{tag}|{defn})
            )+
        )\n*
    '''.format(
        # remove all group name
        hr=re.sub(r'P<[^>]+>', ':', normal['hr']),
        heading=re.sub(r'P<[^>]+>', ':', normal['heading']),
        lheading=re.sub(r'P<[^>]+>', ':', normal['lheading']),
        blockquote=re.sub(r'P<[^>]+>', ':', normal['blockquote']),
        tag='<' + htmltag,
        defn=re.sub(r'P<[^>]+>', r':', normal['def'])
    )

    normal['text'] = r'''(?P<text>[^\n]+)'''

    #------------------
    #   gfm patterns
    #------------------
    gfm = OrderedDict(normal)

    gfm['fences'] = r'''
        (?P<fences>
            [ ]*
            (?P<fences_tag>`{3,})[ ]*(?P<fences_lang>\S+)?[ ]*\n
            (?P<fences_code>[\s\S]+?)
            \s*
            (?P=fences_tag)
            [ ]*
            (?:\n+|$)
        )
    '''

    gfm['nptable'] = r'''
        (?P<nptable>
            [ ]*(?P<nptable_header>\S.*\|.*)\n
            [ ]*(?P<nptable_align>[-:]+[ ]*\|[-| :]*)\n
            (?P<nptable_cells>(?:.*\|.*(?:\n|$))*)
            \n*
        )
    '''

    gfm['table'] = r'''
        (?P<table>
            [ ]*\|(?P<table_header>.+)\n
            [ ]*\|(?P<table_align>[ ]*[-:]+[-| :]*)\n
            (?P<table_cells>(?:[ ]*\|.*(?:\n|$))*)
            \n*
        )
    '''

    gfm['paragraph'] = r'''
        (?P<paragraph>
            (?:
                [^\n]+
                \n?
                (?!{fences}|{hr}|{heading}|{lheading}|{blockquote}|{tag}|{defn})
            )+
        )\n*
    '''.format(
        # remove all group name
        hr=re.sub(r'P<[^>]+>', ':', normal['hr']),
        heading=re.sub(r'P<[^>]+>', ':', normal['heading']),
        lheading=re.sub(r'P<[^>]+>', ':', normal['lheading']),
        blockquote=re.sub(r'P<[^>]+>', ':', normal['blockquote']),
        tag='<' + htmltag,
        defn=re.sub(r'P<[^>]+>', r':', normal['def']),
        fences=re.sub(r'fences', r'_fences', gfm['fences'])
    )

    #------------------
    #   block rules
    #------------------
    normal_rule = re.compile('|'.join([v for k, v in normal.items() if v is not None]), re.X | re.U)

    gfm_rule = re.compile('|'.join([v for k, v in gfm.items() if v is not None]), re.X | re.U)


class InlineRule(object):
    #------------------
    #   normal patterns
    #------------------
    normal = OrderedDict()

    normal['macro'] = r'''(?P<macro>
            <<
                (?P<macro_name>\S+)
                (?P<macro_attrs>
                    (?:[ ]+\S+="\S+"[ ]*)*
                )
            />>
        )
    '''

    normal['escape'] = r'''\\(?P<escape>[\\`*{}\[\]()#+\-.!_>])'''

    normal['autolink'] = r'''<(?P<autolink>[^ >]+(?P<autolink_tag>@|:\/)[^ >]+)>'''

    normal['url'] = None

    normal['tag'] = r'''
        (?P<tag>
            <!--[\s\S]*?-->
            |
            <\/?\w+(?:"[^"]*"|'[^']*'|[^'">])*?>
        )
    '''

    normal['wikilink'] = r'''
        (?P<wikilink>
            \[\[
                (?P<wikilink_name>[^\]\|]*)
                (?:  \|
                    (?P<wikilink_text>[^\]]*)
                )?
            \]\]
        )
    '''

    normal['link'] = r'''
        (?P<link>
            !?\[
                (?P<link_text>{text})
            \]
            \(
                {href}
            \)
        )
    '''.format(
        text=r'''(?:\[[^\]]*\]|[^\]]|\](?=[^\[]*\]))*''',
        href=r'''
            \s*
                <?
                    (?P<link_href>[^\s<>]*?)
                >?
                (?:
                    \s+
                    ['"]
                        (?P<link_title>[\s\S]*?)
                    ['"]
                )?
            \s*'''
    )

    normal['reflink'] = r'''
        (?P<reflink>
            !?\[
                (?P<reflink_text>{text})
            \]
            \s*
            \[(?P<reflink_key>[^\]]*)\]
        )
    '''.format(text=r'(?:\[[^\]]*\]|[^\]]|\](?=[^\[]*\]))*')

    normal['nolink'] = r'''
        (?P<nolink>
            !?\[
                (?P<nolink_text>
                    (?:\[[^\]]*\]|[^\[\]])*
                )
            \]
            (?:\[\])?
        )
    '''

    normal['strong'] = r'''
        (?P<strong>
            __(?P<strong_1>[\s\S]+?)__(?!_)
            |
            \*\*(?P<strong_2>[\s\S]+?)\*\*
            (?!\*)
        )
    '''

    normal['em'] = r'''
        (?P<em>
            \b_(?P<em_1>(?:__|[\s\S])+?)_\b
            |
            \*(?P<em_2>(?:\*\*|[\s\S])+?)\*
            (?!\*)
        )
    '''

    normal['code'] = r'''
        (?P<code_tag>`+)
            \s*(?P<code>[\s\S]*?[^`])\s*
        (?P=code_tag)
        (?!`)
    '''

    normal['br'] = r'''(?P<br>[ ]{2,}\n(?!\s*$))'''

    normal['del'] = None

    normal['text'] = r'''
        (?P<text>
            [\s\S]+?
            (?=
                [\\<!\[_*`]
                |
                [ ]{2,}\n
                |$
            )
        )
    '''

    #------------------
    #   gfm patterns
    #------------------
    gfm = OrderedDict(normal)

    gfm['escape'] = normal['escape'].replace(r'])', r'~|])')

    gfm['url'] = r'''
        (?P<url>
            https?:\/\/
            [^\s<]+
            [^<.,:;"')\]\s]
        )
    '''

    gfm['del'] = r'''
        ~~(?=\S)
        (?P<del>[\s\S]*?\S)
        ~~
    '''

    gfm['text'] = r'''
        (?P<text>
            [\s\S]+?
            (?=
                [\\<!\[_*`~]
                |
                https?://
                |
                [ ]{2,}\n
                |$
            )
        )
    '''

    #---------------------
    #   gfm_break patterns
    #---------------------
    gfm_break = OrderedDict(gfm)

    gfm_break['br'] = normal['br'].replace(r'{2,}', r'*')

    gfm_break['text'] = gfm['text'].replace(r'{2,}', r'*')

    #---------------------
    #   inline rules
    #---------------------
    normal_rule = re.compile('|'.join([v for k, v in normal.items() if v is not None]), re.X | re.U)

    gfm_rule = re.compile('|'.join([v for k, v in gfm.items() if v is not None]), re.X | re.U)

    gfm_break_rule = re.compile('|'.join([v for k, v in gfm_break.items() if v is not None]), re.X | re.U)


# default options
defaults = dict(
    gfm=True,
    breaks=False,
    sanitize=False,
    smartLists=True,
    langPrefix='lang-',
    smartypants=False,
    wikilink=lambda groups: '<a href="{href}" class="wiki">{text}</a>'.format(
        href=groups.wikilink_name,
        text=groups.get('wikilink_text', None) or groups.wikilink_name),
    header_id=False,
    toc=False
)


class Lexer(object):
    __rule_list_item = re.compile(BlockRule.listitem, re.M)
    __rule_list_bullet = re.compile(BlockRule.bullet)

    def __init__(self, options):
        self.logger = logging.getLogger("Lexer")
        self.options = options
        if self.options.gfm:
            self.rule = BlockRule.gfm_rule
        else:
            self.rule = BlockRule.normal_rule

    def lex(self, src):
        self.tokens, self.links = [], {}

        src = re.sub(r'\r\n|\r/', '\n', src)
        src = re.sub(r'\t', '    ', src)
        src = re.sub(r'\n[ ]+\n', '\n\n', src)
        src = re.sub(r'\u00a0/', ' ', src)
        src = re.sub(r'\u2424', '\n', src)
        #src = re.sub(r'^[ ]+$', '', src, flags=re.M)

        self._token(src, True)

        return pdict(tokens=self.tokens, links=self.links)

    def _token(self, src, top=False):
        while len(src) > 0:
            self.logger.debug("Src: %s" % str([src]))
            match = self.rule.match(src)
            g0 = match.group(0)
            groups = pdict([(k, v) for k, v in match.groupdict().items() if v is not None])
            block_name = self._get_block_name(groups)
            self.logger.debug(block_name.title())

            if not top and block_name in ['paragraph', 'def', 'nptable', 'table']:
                # if not top and block_name in 'paragraph', 'def', 'nptable', 'table'
                # insert a text token for the first line of match.group(0), and
                # src = the_remain_lines + src[line(group(0)):]
                splits = g0.split('\n', 1)
                self.tokens.append(pdict(kind='text', text=splits[0]))
                src = '%s%s' % (splits[1] if len(splits) > 1 else '', src[len(g0):])

                self.logger.debug('Text')
                self.logger.debug([splits[0]])
                continue
            else:
                ret = getattr(self, '_token_%s' % block_name)(groups)
                src = src[len(g0):] if ret is None else '%s%s' % (ret, src[len(g0):])

            self.logger.debug(block_name.title())
            self.logger.debug([g0])

    def _get_block_name(self, groups):
        for k, v in groups.items():
            if k.find('_') < 0:
                return k

    def _token_macro(self, groups):
        groups.kind = 'macro'
        self.tokens.append(groups)

    def _token_newline(self, groups):
        self.tokens.append(pdict(kind='space'))

    def _token_code(self, groups):
        self.tokens.append(pdict(
            kind='code',
            text=re.sub(r'\n+$', '', groups['code'])
        ))

    def _token_fences(self, groups):
        self.tokens.append(pdict(
            kind='code',
            lang=groups.get('fences_lang', None),
            text=re.sub(r'\n+$', '', groups.fences_code)
        ))

    def _token_heading(self, groups):
        self.tokens.append(pdict(
            kind='heading',
            depth=len(groups.heading_depth),
            text=groups.heading_text
        ))

    def _token_lheading(self, groups):
        self.tokens.append(pdict(
            kind='heading',
            depth=1 if groups.lheading_depth == '=' else 2,
            text=groups.lheading_text
        ))

    def _token_hr(self, groups):
        self.tokens.append(pdict(
            kind='hr'
        ))

    def _token_blockquote(self, groups):
        self.tokens.append(pdict(kind='blockquote_start'))

        # remove ' >'
        body = re.sub(r'^[ ]*>[ ]?', '', groups.blockquote, flags=re.M)
        # Recurse.
        self._token(body, False)

        self.tokens.append(pdict(kind='blockquote_end'))

    def _token_list(self, groups):
        ret = None
        bull = groups.list_bull
        body = groups.list

        self.tokens.append(pdict(kind='list_start', ordered=len(bull) > 1))

        # Get each top-level item.
        items = [m.group(0) for m in self.__rule_list_item.finditer(body)]

        self.logger.debug("List Items: %s" % str(items))

        next_loose = False
        i, l = 0, len(items)

        while i < l:
            item = items[i]

            # Remove the list item's bullet
            # so it is seen as the next token.
            space = len(item)
            item = re.sub(r'^[ ]*([*+-]|\d+\.)[ ]+', '', item)

            # Outdent whatever the list item contains. Hacky.
            if ~item.find('\n '):
                space -= len(item)

            # delete tab
            item = re.sub(r'^[ ]{1,%d}' % space, '', item, flags=re.M)

            self.logger.debug("List Item: %s" % str([item]))

            # Determine whether the next list item belongs here.
            # Backpedal if it does not belong in this list.
            if self.options.smartLists and i != l - 1:
                b = self.__rule_list_bullet.match(items[i + 1].lstrip()).group(0)[0]
                if (bull != b) and not (len(bull) > 1 and len(b) > 1):
                    ret = '\n'.join(items[i + 1:])
                    i = l - 1

            # Determine whether item is loose or not.
            # Use: /(^|\n)(?! )[^\n]+\n\n(?!\s*$)/
            # for discount behavior.
            loose = next_loose or re.search(r'\n\n(?!\s*$)', item)
            if i != l - 1:
                next_loose = item[-1] == '\n'
                if not loose:
                    loose = next_loose

            self.tokens.append(pdict(
                kind='loose_item_start' if loose else 'list_item_start'
            ))

            # Recurse.
            self._token(item, False)

            self.tokens.append(pdict(kind='list_item_end'))

            i += 1

        self.tokens.append(pdict(kind='list_end'))

        return ret

    def _token_html(self, groups):
        self.tokens.append(pdict(
            kind='paragraph' if self.options.sanitize else 'html',
            pre=(groups.get('html_tag', None) == 'pre' or groups.get('html_tag', None) == 'script'),
            text=groups.html
        ))

    def _token_def(self, groups):
        key = re.sub(r'\s+', ' ', groups.def_key).lower()
        self.links[key] = pdict(
            href=groups.def_href,
            title=groups.get('def_title', None)
        )

    def _token_paragraph(self, groups):
        self.tokens.append(pdict(kind='paragraph', text=groups.paragraph.rstrip()))

    def _token_text(self, groups):
        self.tokens.append(pdict(kind='text', text=groups.text))

    __rule_nptable_line_trim = re.compile(r'[ ]*(?=\|)|(?<=\|)[ ]*')

    __rule_table_line_trim = re.compile(r'^\|[ ]*|\|\s*$|[ ]*(?=\|)|(?<=\|)[ ]*', re.M)

    def _token_nptable(self, groups):
        header = groups.nptable_header.strip()
        align = groups.nptable_align.strip()
        cells = groups.nptable_cells.strip()

        rule = self.__rule_nptable_line_trim

        item = pdict(
            kind='table',
            header=re.split(r'\|', rule.sub('', header)),
            align=re.split(r'\|', rule.sub('', align)),
            cells=re.split(r'\n', rule.sub('', cells))
        )

        self._do_token_table(item)

    def _token_table(self, groups):
        header = groups.table_header.strip()
        align = groups.table_align.strip()
        cells = groups.table_cells.strip()

        rule = self.__rule_table_line_trim

        item = pdict(
            kind='table',
            header=re.split(r'\|', rule.sub('', header)),
            align=re.split(r'\|', rule.sub('', align)),
            cells=re.split(r'\n', rule.sub('', cells))
        )

        self._do_token_table(item)

    def _do_token_table(self, item):
        cols = len(item.header)
        for i in range(len(item.align)):
            if re.match(r'^-+:$', item.align[i]):
                item.align[i] = 'right'
            elif re.match(r'^:-+:$', item.align[i]):
                item.align[i] = 'center'
            elif re.match(r'^:-+$', item.align[i]):
                item.align[i] = 'left'
            else:
                item.align[i] = None
        for i in range(len(item.cells)):
            item.cells[i] = re.split(r'\|', item.cells[i])

            # check the tail cell.
            len_col = len(item.cells[i])
            if len_col < cols:
                item.cells[i].append("")

        self.tokens.append(item)


def escape(html, encode=False):
    if not encode:
        html = re.sub(r'&(?!#?\w+;)', '&amp;', html)
    else:
        html = re.sub(r'&', '&amp;', html)
    html = re.sub(r'<', '&lt;', html)
    html = re.sub(r'>', '&gt;', html)
    html = re.sub(r'"', '&quot;', html)
    html = re.sub(r"'", '&#39;', html)
    return html


class Macro(object):
    def execute(self, **kwargs):
        raise NotImplementedError()


class MacroMixin(object):
    rule_marco_attrs = re.compile(r'(\S+)="(\S+)"')
    macros = pdict()

    def register_macro(self, name, macro_type):
        assert issubclass(macro_type, Macro)
        self.macros[name] = macro_type()

    def call_macro(self, groups):
        name = groups.macro_name
        parameters = pdict()
        if groups.macro_attrs:
            for m in self.rule_marco_attrs.finditer(groups.macro_attrs):
                key, val = m.group(1, 2)
                parameters[key] = val
        parameters.macro_body = groups.get('macro_body', None)
        return self.macros[name].execute(**parameters)


class InlineParser(MacroMixin):
    def __init__(self, links, options):
        self.logger = logging.getLogger("InLineLexer")

        self.options = options
        if self.options.gfm:
            if self.options.breaks:
                self.patterns = InlineRule.gfm_break
                self.rule = InlineRule.gfm_break_rule
            else:
                self.patterns = InlineRule.gfm
                self.rule = InlineRule.gfm_rule
        else:
            self.patterns = InlineRule.normal
            self.rule = InlineRule.normal_rule

        for name, macro_class in self.options.get('inline_macros', {}).items():
            self.register_macro(name, macro_class)

        self.links = links

    def parse(self, src):
        buffer = []
        while len(src) > 0:
            match = self.rule.match(src)
            g0 = match.group(0)
            groups = pdict([(k, v) for k, v in match.groupdict().items() if v is not None])
            inline_name = self._get_inline_name(groups)

            if inline_name == 'reflink' or inline_name == 'nolink':
                key, text, title = None, None, None
                if inline_name == 'reflink':
                    key = groups.reflink_key or groups.reflink_text
                    text = groups.reflink_text
                else:
                    text = groups.nolink_text
                    key = text

                key = re.sub(r'\s+', ' ', key).lower()
                link = self.links.get(key, None)
                if not link or not link.href:
                    buffer.append(g0[0])
                    src = src[1:]
                    continue
                else:
                    link.text = text
                    link.imaged = g0[0] == '!'
                    src = src[len(g0):]
                    buffer.append(self._do_parse_link(link))
            else:
                buffer.append(getattr(self, '_parse_%s' % inline_name)(groups))
                src = src[len(g0):]

        return ''.join(buffer)

    def _get_inline_name(self, groups):
        for k, v in groups.items():
            if k.find('_') < 0:
                return k

    def _parse_macro(self, groups):
        return self.call_macro(groups)

    def _parse_escape(self, groups):
        return groups.escape

    def _parse_autolink(self, groups):
        tag = groups.autolink_tag
        body = groups.autolink
        href, text = None, None
        if tag == '@':
            text = self._mangle(body[7:]) if body[6] == ':' else self._mangle(body)
            href = self._mangle('mailto:%s' % text)
        else:
            text = escape(body)
            href = text
        return '<a href="%s">%s</a>' % (href, text)

    def _parse_url(self, groups):
        return '<a href="{url}">{url}</a>'.format(url=escape(groups.url))

    def _parse_tag(self, groups):
        tag = groups.tag
        return escape(tag) if self.options.sanitize else tag

    def _do_parse_link(self, link):
        if not link.imaged:
            return '<a href="{href}"{title}>{text}</a>'.format(
                href=escape(link.href),
                title=' title="%s"' % escape(link.title) if link.title else '',
                text=self.parse(link.text)
            )
        else:
            return '<img src="{href}" alt="{alt}"{title} />'.format(
                href=escape(link.href),
                alt=escape(link.text),
                title=' title="%s"' % escape(link.title) if link.title else ''
            )

    def _parse_link(self, groups):
        link = pdict(
            text=groups.link_text,
            href=groups.link_href,
            title=groups.get('link_title', None),
            imaged=groups.link[0] == '!')

        return self._do_parse_link(link)

    def _parse_wikilink(self, groups):
        return self.options.wikilink(groups)

    def _parse_strong(self, groups):
        text = groups.get('strong_1', None) or groups.get('strong_2', None)
        return '<strong>%s</strong>' % self.parse(text)

    def _parse_em(self, groups):
        text = groups.get('em_1', None) or groups.get('em_2', None)
        return '<em>%s</em>' % self.parse(text)

    def _parse_code(self, groups):
        return '<code>%s</code>' % escape(groups.code, True)

    def _parse_del(self, groups):
        return '<del>%s</del>' % groups['del']

    def _parse_br(self, groups):
        return '<br />'

    def _parse_text(self, groups):
        return escape(self._smartypants(groups.text))

    def _smartypants(self, text):
        if not self.options.smartypants:
            return text
        text = re.sub(r'--', '—', text)
        text = re.sub(r"'([^']*)'", r'‘\1’', text)
        text = re.sub(r'"([^"]*)"', r'“\1”', text)
        text = re.sub(r'\.{3}', '…', text)
        return text

    def _mangle(self, text):
        out = []
        for i in text:
            ch = ord(text[i])
            ch = 'x%s' % str(int(str(ch), 16))
            out.append('&#%s;' % str(ch))
        return ''.join(out)


class Parser(MacroMixin):
    def __init__(self, **options):
        self.logger = logging.getLogger("Parser")
        self.options = pdict(defaults, **options)
        for name, macro_class in self.options.get('macros', {}).items():
            self.register_macro(name, macro_class)

    def parse(self, text):
        doc = Lexer(self.options).lex(text)
        self.tokens = doc.tokens
        self.logger.debug(self.tokens)
        self.logger.debug(doc.links)
        self.inline = InlineParser(doc.links, self.options)

        #current token
        self.token = None

        if self.options.header_id:
            self.headers = []
            self.header_id = 1

        buffer = []
        while self.__next() is not None:
            html = self._do_parse()
            buffer.append(html)

        if self.options.header_id and self.options.toc:
            buffer.insert(0, self._parse_toc())

        return ''.join(buffer)

    def _parse_toc(self):
        if self.options.header_id and self.options.toc:
            if len(self.headers) == 0:
                return ''

            ret = ['<div class="toc">\n<ul>']
            stack = []

            while len(self.headers) > 0:
                current = self.headers.pop(0)
                if len(stack) == 0:
                    ret.extend(['<li>', '<ul>'] * (current.depth - 1))
                    ret.append('<li>')
                    ret.append('<a href="#{header_id}">{text}</a>'.format(
                        header_id=current.header_id,
                        text=current.text
                    ))
                    ret.append('</li>')
                    stack.append(current)
                    continue
                if current.depth == stack[-1].depth:
                    ret.append('<li>')
                    ret.append('<a href="#{header_id}">{text}</a>'.format(
                        header_id=current.header_id,
                        text=current.text
                    ))
                    ret.append('</li>')
                elif current.depth < stack[-1].depth:
                    offset = stack[-1].depth - current.depth
                    ret.extend(['</ul>', '</li>'] * offset)
                    while len(stack) > 0 and current.depth < stack[-1].depth:
                        stack.pop()
                    ret.append('<li>')
                    ret.append('<a href="#{header_id}">{text}</a>'.format(
                        header_id=current.header_id,
                        text=current.text
                    ))
                    ret.append('</li>')
                    stack.append(current)
                elif current.depth > stack[-1].depth:
                    # pop  the end '</li>'
                    ret.pop()

                    offset = current.depth - stack[-1].depth
                    ret.extend(['<ul>', '<li>'] * offset)
                    ret.append('<a href="#{header_id}">{text}</a>'.format(
                        header_id=current.header_id,
                        text=current.text
                    ))
                    ret.append('</li>')
                    stack.append(current)
            ret.extend(['</ul>', '</li>'] * (current.depth - 1))
            ret.extend(['</ul>', '</div>\n'])
            return '\n'.join(ret)

    def _do_parse(self):
        kind = self.token.kind
        func = getattr(self, '_parse_%s' % kind, None)
        if func:
            return func()
        else:
            self.logger.debug("Not found func for token: " + str(self.token))

    def __next(self):
        if len(self.tokens) > 0:
            self.token = self.tokens.pop(0)
        else:
            self.token = None
        return self.token

    def _parse_space(self):
        return ''

    def _parse_macro(self):
        return self.inline.parse(self.call_macro(self.token))

    def _parse_hr(self):
        return '<hr />\n'

    def __header_id(self):
        ret = self.header_id
        self.header_id += 1
        return ret

    def _parse_heading(self):
        if self.options.header_id:
            if self.token.depth < 5:
                self.token.header_id = self.__header_id()
                self.headers.append(self.token)
            else:
                self.token.header_id = None
            return '<h{depth}>{text}{header_id}</h{depth}>\n'.format(
                depth=self.token.depth,
                text=self.inline.parse(self.token.text),
                header_id='<a name="%s"></a>' % self.token.header_id if self.token.header_id else ''
            )
        return '<h{depth}>{text}</h{depth}>\n'.format(
            depth=self.token.depth,
            text=self.inline.parse(self.token.text)
        )

    def _parse_code(self):
        self.token.text = escape(self.token.text, self.token.get('escaped', True))
        lang = self.token.get('lang', None)
        if lang:
            lang = ' class="%s%s"' % (self.options.langPrefix, lang)
        else:
            lang = ''
        return '<pre>\n<code{lang}>\n{text}\n</code>\n</pre>\n'.format(
            lang=lang,
            text=self.token.text
        )

    def _parse_table(self):
        body = ['<thead>\n<tr>\n']
        for i in range(len(self.token.header)):
            heading = self.inline.parse(self.token.header[i])
            if self.token.align[i]:
                body.append('<th align="%s">%s</th>' % (self.token.align[i], heading))
            else:
                body.append('<th>%s</th>' % heading)
        body.append('</tr>\n</thead>\n')
        body.append('<tbody>\n')
        for i in range(len(self.token.cells)):
            row = self.token.cells[i]
            body.append('<tr>\n')
            for j in range(len(row)):
                cell = self.inline.parse(row[j])
                if j < len(self.token.align) and self.token.align[j]:
                    body.append('<td align="%s">%s</td>\n' % (self.token.align[j], cell))
                else:
                    body.append('<td>%s</td>' % cell)
            body.append('</tr>\n')
        body.append('</tbody>\n')

        return '<table>\n%s</table>\n' % ''.join(body)

    def _parse_blockquote_start(self):
        body = []
        while self.__next().kind != 'blockquote_end':
            body.append(self._do_parse())
        return '<blockquote>\n%s</blockquote>\n' % ''.join(body)

    def _parse_list_start(self):
        kind = 'ol' if self.token.ordered else 'ul'

        body = []
        while self.__next().kind != 'list_end':
            body.append(self._do_parse())

        return '<{kind}>\n{body}</{kind}>\n'.format(
            kind=kind,
            body=''.join(body)
        )

    def _parse_list_item_start(self):
        body = []
        while self.__next().kind != 'list_item_end':
            if self.token.kind == 'text':
                body.append(self._do_parse_text())
            else:
                body.append(self._do_parse())

        return '<li>%s</li>\n' % ''.join(body)

    def _parse_loose_item_start(self):
        body = []
        while self.__next().kind != 'list_item_end':
            body.append(self._do_parse())

        return '<li>%s</li>\n' % ''.join(body)

    def _parse_html(self):
        if not self.token.pre:
            return self.inline.parse(self.token.text)
        else:
            return self.token.text

    def _parse_paragraph(self):
        return '<p>%s</p>\n' % self.inline.parse(self.token.text)

    def _parse_text(self):
        return '<p>%s</p>\n' % self._do_parse_text()

    def _do_parse_text(self):
        body = [self.token.text]

        while len(self.tokens) > 0 and self.tokens[0].kind == 'text':
            body.append('\n%s' % self.__next().text)

        return self.inline.parse(''.join(body))


def marked(text, **options):
    return Parser(**options).parse(text)
