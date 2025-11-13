from __future__ import annotations      # To avoid type hint warnings with the Node class


class Node:
    def __init__(self, red: bool, parent: Node | None, left: Node, right: Node):
        self.parent = parent
        self.left = left
        self.right = right
        self.red = red
        self.key = None


# MemTable implemented as a Red Black Tree
# For O(log n) lookups, insertions, and deletions of sorted keys
class MemTable:
    NIL = Node(False, None, None, None)

    def __init__(self):
        self.root = MemTable.NIL
        self.elements = 0

    # ==========================================================================================================
    # CORE FUNCTIONS ===========================================================================================

    def insert(self, key: bytes) -> bool:
        if self.elements == 0:
            self.root = Node(False, None, MemTable.NIL, MemTable.NIL)
            self.root.key = key
            self.elements = 1
            return True

        parent = None
        current = self.root

        while current is not MemTable.NIL:
            parent = current    # Cache the parent node
            if key == current.key: return False         # Return false if the key already exists
            current = current.left if key < current.key else current.right      # Traverse deeper into the tree

        new_node = Node(True, parent, MemTable.NIL, MemTable.NIL)
        new_node.key = key

        if key < parent.key:            # If the key is less than the parent key, insert as a left child
            parent.left = new_node
        else:                           # If the key is greater than the parent key, insert as a right child
            parent.right = new_node

        self.fix_insert(new_node)      # Call fix insert to maintain Red Black Tree properties
        self.elements += 1
        return True
    

    def fix_insert(self, node: Node) -> None:
        # Violations only occur when the parent is red
        while node is not self.root and node.parent.red:
            grandparent = node.parent.parent

            # Parent is a left child
            if node.parent is grandparent.left:
                # CASE 1: Parent is red and uncle is red (Recolor)
                if grandparent.right.red:
                    node.parent.red = False
                    grandparent.right.red = False
                    grandparent.red = True
                    node = grandparent
                # CASE 2: Parent is red and uncle is black (Rotate)
                else:
                    if node == node.parent.right:
                        node = node.parent
                        self.left_rotate(node)

                    self.right_rotate(grandparent)
                    node.parent.red = grandparent.red
                    grandparent.red = True

            # Parent is a right child
            else:
                # CASE 1: Parent is red and uncle is red (Recolor)
                if grandparent.left.red:
                    node.parent.red = False
                    grandparent.left.red = False
                    grandparent.red = True
                    node = grandparent
                # CASE 2: Parent is red and uncle is black (Rotate)
                else:
                    if node == node.parent.left:
                        node = node.parent
                        self.right_rotate(node)

                    self.left_rotate(grandparent)
                    node.parent.red = grandparent.red
                    grandparent.red = True

        self.root.red = False


    def get(self, key: bytes) -> bytes | None:
        # Standard BST traversal, return the key if it exists, or else return None
        node = self.root
        while node is not MemTable.NIL:
            if key == node.key: return node.key
            node = node.left if key < node.key else node.right
        return
    

    def remove(self, key: bytes) -> bool:
        # Standard BST traversal, find the node to be deleted
        node = self.root
        while node is not MemTable.NIL:
            if key == node.key: break
            node = node.left if key < node.key else node.right

        # If the key does not exist, return False
        if node is MemTable.NIL: return False

        # Call fix remove on the node to handle all cases in Red Black Tree
        self.fix_remove(node)
        self.elements -= 1
        return True
    

    def fix_remove(self, node: Node) -> None:
        # 'node' refers to the node to be removed
        while True:
            # If node has two non-NIL children
            if node.left is not MemTable.NIL and node.right is not MemTable.NIL:
                # Replace the node key with its successor's key and do fix_remove on the successor node
                temp = self.node_successor(node)
                node.key = temp.key
                node = temp

            # If node either has one non-NIL child or two NIL children
            else:
                temp = node.left if node.left is not MemTable.NIL else node.right

                if temp is MemTable.NIL:
                    # If node is red and has NIL children, physically delete the node
                    if node.red: self.delete_node(node)
                    # If node is black and has NIL children, a double black occurs and must be handled
                    else: self.fix_double_black(node)
                    
                # If node is black and has one red child with NIL children
                else:
                    node.key = temp.key
                    self.delete_node(temp)
                return
            

    def fix_double_black(self, node: Node) -> None:
        while True:
            if node is self.root: return

            parent = node.parent
            sibling = parent.left if node != parent.left else parent.right

            # If sibling is RED
            if sibling.red:
                parent.red = True
                sibling.red = False
                if node is parent.left: self.left_rotate(parent)
                else: self.right_rotate(parent)

            elif sibling.left.red:

                # Sibling is black. BOTH children are RED
                if sibling.right.red:
                    sibling.red = parent.red
                    parent.red = False
                    sibling.left.red = False
                    sibling.right.red = False

                    if node is parent.left:
                        self.left_rotate(parent)
                    else:
                        self.right_rotate(parent)

                # Sibling is black. Only the LEFT child is red, it's NEAR the double black
                elif node is parent.left:
                    sibling.red = True
                    sibling.left.red = False
                    self.right_rotate(sibling)

                # Sibling is black. Only the LEFT child is RED, it's FAR from the double black
                else:
                    sibling.red = parent.red
                    parent.red = False
                    sibling.left.red = False
                    self.left_rotate(parent)
                    return

            elif sibling.right.red:

                # Sibling is black. Only the RIGHT child is RED, it's NEAR the double black
                if node is parent.right:
                    sibling.red = True
                    sibling.right.red = False
                    self.left_rotate(sibling)

                # Sibling is black. Only the RIGHT child is RED, it's FAR from the double black
                else:
                    sibling.red = parent.red
                    parent.red = False
                    sibling.right.red = False
                    self.right_rotate(parent)
                    return
                
            # If BLACK sibling with BLACK children
            else:
                sibling.red = True

                if node.left is MemTable.NIL and node.right is MemTable.NIL:
                    self.delete_node(node)

                if parent.red:
                    parent.red = False
                    return
                else: node = parent


    def range_lookup(self, lower_bound: bytes, upper_bound: bytes) -> bytearray:
        results = bytearray()
        self.range_lookup_traverse(self.root, lower_bound, upper_bound, results)
        return results

    def range_lookup_traverse(self, node: Node, lower_bound: bytes, upper_bound: bytes, results: list) -> None:
        if node is MemTable.NIL:
            return
        
        if node.key > lower_bound:
            self.range_lookup_traverse(node.left, lower_bound, upper_bound, results)
        if lower_bound <= node.key <= upper_bound:
            results.extend(node.key)
        if node.key < upper_bound:
            self.range_lookup_traverse(node.right, lower_bound, upper_bound, results)

    # ==========================================================================================================
    # HELPER FUNCTIONS =========================================================================================
    
    def right_rotate(self, node: Node) -> None:
        new_parent = node.left

        if node is not self.root:
            if node is node.parent.left:
                node.parent.left = new_parent
            else:
                node.parent.right = new_parent
            new_parent.parent = node.parent
        else:
            self.root = new_parent
            new_parent.parent = None

        node.parent = new_parent
        node.left = new_parent.right
        new_parent.right.parent = node
        new_parent.right = node

    
    def left_rotate(self, node: Node) -> None:
        new_parent = node.right

        if node is not self.root:
            if node is node.parent.left:
                node.parent.left = new_parent
            else:
                node.parent.right = new_parent
            new_parent.parent = node.parent
        else:
            self.root = new_parent
            new_parent.parent = None

        node.parent = new_parent
        node.right = new_parent.left
        new_parent.left.parent = node
        new_parent.left = node


    def node_successor(self, node: Node) -> Node:
        node = node.right
        while node.left is not MemTable.NIL:
            current = current.left
        return node;


    def delete_node(self, node: Node) -> None:
        if node is node.parent.left: node.parent.left = MemTable.NIL
        else: node.parent.right = MemTable.NIL
        del node

    # ==========================================================================================================
    # SORT FUNCTIONALITY =======================================================================================

    def in_order(self):
        lst = []
        self.in_order_traverse(self.root, lst)
        return lst

    def in_order_traverse(self, node, lst):
        if node is MemTable.NIL: return
        self.in_order_traverse(node.left, lst)
        lst.append(node.key)
        self.in_order_traverse(node.right, lst)

    # ==========================================================================================================
    # DUNDER METHODS ===========================================================================================

    def __delitem__(self, key: bytes) -> bytes:
        return self.remove(key)
    
    def __iter__(self):
        yield from self.iter_traverse(self.root)
    def iter_traverse(self, node):
        if node == MemTable.NIL: return
        yield from self.iter_traverse(node.left)
        yield node.key
        yield from self.iter_traverse(node.right)

    def __contains__(self, key: bytes) -> bool:
        return self.get(key) is not None

    def __str__(self):
        return f"{{{", ".join(str(v) for v in self.in_order())}}}"
    
    def __len__(self) -> int:
        return self.elements
    
    def __bool__(self) -> bool:
        return self.elements > 0