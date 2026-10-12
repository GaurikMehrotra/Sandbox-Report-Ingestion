"""Non-destructive normalization. Raw evidence is always kept separately."""

from copy import deepcopy

from .ioc import KEY_TYPES, normalize


def observation(value, kind, warnings):
    result = deepcopy(value)

    def walk(node):
        if isinstance(node, dict):
            for key, child in list(node.items()):
                ioc_type = KEY_TYPES.get(key.lower())
                if isinstance(child, str) and ioc_type:
                    normalized = normalize(ioc_type, child)
                    if normalized is not None:
                        node[key] = normalized
                    elif ioc_type not in {"filename", "process_name"}:
                        warnings.append(
                            "invalid " + ioc_type + " field retained; excluded from IOCs"
                        )
                elif key in {"process_id", "parent_id", "pid", "ppid"}:
                    if isinstance(child, int) and not isinstance(child, bool) and child >= 0:
                        node[key] = str(child)
                    elif isinstance(child, str) and child.isdecimal():
                        node[key] = str(int(child))
                    else:
                        warnings.append("invalid process identifier retained")
                else:
                    walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)

    walk(result)
    return result
