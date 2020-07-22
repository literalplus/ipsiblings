# trie.py
#
# (c) 2018 Marco Starke
#
import re


class Trie:
    # author:         rex
    # blog:           http://iregex.org
    # filename        trie.py
    # created:        2010-08-01 20:24
    # source uri:     http://iregex.org/blog/trie-in-python.html

    # Trie <=> PrefixTree or RadixTree (ordered tree)

    """
    Python regex trie. Creates a Trie out of a list of words (e.g. IP addresses).
    The trie can be exported to a regex pattern.
    The corresponding regex should match much faster than a simple regex union.

    Example:

    def trie_regex(items):
      trie = Trie()
      for item in items:
        trie.add(item)
      return re.compile(r'^' + trie.pattern(), re.IGNORECASE)

    def ignore(item, regex):
      return regex.match(item)


    union = trie_regex(items_to_match)

    for string in big_item_list:
      do_something_with(ignore(string, union))
    """

    def __init__(self):
        self.data = {}

    def add(self, word):
        ref = self.data
        for char in word:
            ref[char] = char in ref and ref[char] or {}
            ref = ref[char]
        ref[''] = 1

    def dump(self):
        return self.data

    def quote(self, char):
        return re.escape(char)

    def _pattern(self, pData):
        data = pData
        if '' in data and len(data.keys()) == 1:
            return None

        alt = []
        cc = []
        q = 0
        for char in sorted(data.keys()):
            if isinstance(data[char], dict):
                try:
                    recurse = self._pattern(data[char])
                    alt.append(self.quote(char) + recurse)
                except:
                    cc.append(self.quote(char))
            else:
                q = 1
        cconly = not len(alt) > 0

        if len(cc) > 0:
            if len(cc) == 1:
                alt.append(cc[0])
            else:
                alt.append('[' + ''.join(cc) + ']')

        if len(alt) == 1:
            result = alt[0]
        else:
            result = '(?:' + '|'.join(alt) + ')'

        if q:
            if cconly:
                result += '?'
            else:
                result = '(?:{0})?'.format(result)
        return result

    def pattern(self):
        return self._pattern(self.dump())
