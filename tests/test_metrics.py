from drbt.metrics import ConfusionMatrix


def test_confusion_matrix_math():
    cm = ConfusionMatrix(tp=8, fp=2, fn=4, tn=86)
    assert cm.alerts == 10
    assert cm.precision == 0.8
    assert round(cm.recall, 4) == round(8 / 12, 4)
    assert round(cm.f1, 4) == round(2 * 0.8 * (8 / 12) / (0.8 + 8 / 12), 4)
    assert round(cm.false_positive_rate, 4) == round(2 / 88, 4)


def test_confusion_matrix_empty_is_zero_not_error():
    cm = ConfusionMatrix()
    assert cm.precision == 0.0
    assert cm.recall == 0.0
    assert cm.f1 == 0.0
    assert cm.false_positive_rate == 0.0
