from guardpost.funchelper import args_to_dict_getter


def test_args_to_dict_getter():

    def method(a, b, c):
        return

    getter = args_to_dict_getter(method)

    assert {'a': 1, 'b': 2, 'c': 3} == getter((1, 2, 3), {})

    assert {'a': 1, 'b': 2, 'c': 3} == getter((1, 2), {'c': 3})

    assert {'a': 1, 'b': 6, 'c': 3} == getter((1, 6), {'c': 3})

    assert {'a': 2, 'b': 5, 'c': 3} == getter((), {'a': 2, 'b': 5, 'c': 3})



def test_args():

    def my(request):
        print(request)

    def some(*args, **kwargs):

        return my(*args, **kwargs)

    some(object())
