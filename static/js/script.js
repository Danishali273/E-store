// Common JavaScript functions for E-Store - Mobile Optimized

// Mobile detection
const isMobile = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);

// Debounce function to prevent// Initial fetch of cart count on page load
function fetchInitialCartCount() {
    const badges = document.getElementById('cart-count-badge') || document.getElementById('cart-count-badge-mobile');
    if (badges) { // Only if user is logged in
        fetch('/cart_count')
            .then(response => response.json())
            .then(data => updateCartCount(data.count))
            .catch(error => console.error('Error fetching cart count:', error));
    }
}

// Debounce function to prevent rapid firing of events (e.g., typing in quantity input)
const debounce = (func, delay = 500) => {
    let timeoutId;
    return (...args) => {
        clearTimeout(timeoutId);
        timeoutId = setTimeout(() => {
            func.apply(this, args);
        }, delay);
    };
};

// Add to cart functionality
function addToCart(productId, quantity = 1) {
    const button = document.querySelector(`.add-to-cart[data-product-id="${productId}"]`);
    if (!button || button.disabled) return;
    
    const originalText = button.innerHTML;
    button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Adding...';
    button.disabled = true;
    
    fetch('/add_to_cart', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `product_id=${productId}&quantity=${quantity}`
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showAlert(data.message, 'success');
            updateCartCount(data.cart_count);
            
            const cartIcon = document.querySelector('.fa-shopping-cart');
            if (cartIcon) {
                cartIcon.classList.add('fa-bounce');
                setTimeout(() => cartIcon.classList.remove('fa-bounce'), 1000);
            }
        } else {
            showAlert(data.message || 'Error adding to cart', 'danger');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showAlert('Error adding to cart. Please try again.', 'danger');
    })
    .finally(() => {
        button.innerHTML = originalText;
        button.disabled = false;
    });
}

// Show alert/notification toast
function showAlert(message, type = 'info') {
    const icons = {
        success: 'fa-check-circle',
        danger: 'fa-exclamation-circle',
        warning: 'fa-exclamation-triangle',
        info: 'fa-info-circle'
    };
    const toastId = 'toast-' + Date.now();
    const toastHtml = `
        <div class="toast" id="${toastId}" role="alert" aria-live="assertive" aria-atomic="true">
            <div class="toast-header bg-${type} text-white">
                <i class="fas ${icons[type]} me-2"></i>
                <strong class="me-auto">${type.charAt(0).toUpperCase() + type.slice(1)}</strong>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="toast" aria-label="Close"></button>
            </div>
            <div class="toast-body">${message}</div>
        </div>`;
    const toastContainer = document.querySelector('.toast-container');
    toastContainer.insertAdjacentHTML('beforeend', toastHtml);
    const toastElement = document.getElementById(toastId);
    const toast = new bootstrap.Toast(toastElement, { delay: 3000 });
    toast.show();
    toastElement.addEventListener('hidden.bs.toast', () => toastElement.remove());
}

// -- DYNAMIC CART UPDATE FUNCTIONS --

// **FIXED**: Dedicated function for removing items
function removeCartItem(cartItemId) {
    const confirmMessage = isMobile ? 'Remove item?' : 'Are you sure you want to remove this item?';
    if (!confirm(confirmMessage)) {
        return;
    }

    const itemRow = document.querySelector(`.cart-item[data-item-id="${cartItemId}"]`);
    if (!itemRow) return;

    itemRow.style.opacity = '0.5';

    // Directly call the fetch API with quantity=0
    fetch('/update_cart', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `cart_item_id=${cartItemId}&quantity=0`
    })
    .then(response => response.json())
    .then(data => {
        if (data.success && data.item_removed) {
            showAlert(data.message, 'success');
            
            // Animate out and remove the element from the DOM
            itemRow.style.transition = 'opacity 0.3s, transform 0.3s';
            itemRow.style.transform = 'translateX(50px)';
            itemRow.style.opacity = '0';
            setTimeout(() => {
                itemRow.remove();
                // If the cart is now empty, reload to show the "empty cart" message
                if (document.querySelectorAll('.cart-item').length === 0) {
                    location.reload(); 
                }
            }, 300);

            // Update summary and counts
            updateOrderSummary(data);
            updateCartCount(data.cart_count);
        } else {
            // Handle cases where the server failed to remove the item
            showAlert(data.message || 'Error removing item', 'danger');
            itemRow.style.opacity = '1';
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showAlert('Error removing item. Please try again.', 'danger');
        itemRow.style.opacity = '1';
    });
}


// Core function to update cart item quantity (for +/-, or manual input)
function updateCartQuantity(cartItemId, change, isInput = false) {
    const itemRow = document.querySelector(`.cart-item[data-item-id="${cartItemId}"]`);
    if (!itemRow) return;

    const quantityInput = itemRow.querySelector('input[type="number"]');
    const currentQuantity = parseInt(quantityInput.value);
    let newQuantity;

    if (isInput) {
        newQuantity = parseInt(change);
        if (isNaN(newQuantity) || newQuantity < 1) {
            // If input is invalid, just revert to the old quantity.
            quantityInput.value = currentQuantity;
            return;
        }
    } else {
        newQuantity = currentQuantity + parseInt(change);
    }
    
    // If quantity becomes 0 or less via buttons, trigger remove flow
    if (newQuantity < 1) {
        removeCartItem(cartItemId);
        return;
    }
    
    itemRow.style.opacity = '0.5';

    fetch('/update_cart', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `cart_item_id=${cartItemId}&quantity=${newQuantity}`
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            quantityInput.value = newQuantity;
            const itemTotalEl = document.getElementById(`item-total-${cartItemId}`);
            if (itemTotalEl) itemTotalEl.textContent = `Rs. ${data.item_total}`;
            
            updateOrderSummary(data);
            updateCartCount(data.cart_count);
        } else {
            showAlert(data.message || 'Error updating cart', 'danger');
            // Revert to max available quantity if server reports an error
            quantityInput.value = data.max_quantity || currentQuantity;
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showAlert('Error updating cart. Please try again.', 'danger');
        quantityInput.value = currentQuantity;
    })
    .finally(() => {
        itemRow.style.opacity = '1';
    });
}

// Debounced version for direct input changes
const debouncedUpdateCart = debounce(updateCartQuantity, 500);

function updateOrderSummary(data) {
    const subtotalEl = document.getElementById('cart-subtotal');
    const taxEl = document.getElementById('cart-tax');
    const totalEl = document.getElementById('cart-total');
    const countEl = document.getElementById('cart-item-count');

    if (subtotalEl) subtotalEl.textContent = `Rs. ${data.cart_subtotal}`;
    if (taxEl) taxEl.textContent = `Rs. ${data.cart_tax}`;
    if (totalEl) totalEl.textContent = `Rs. ${data.cart_total}`;
    if (countEl) countEl.textContent = data.cart_count;
}

// Update cart count in navigation
function updateCartCount(count) {
    const badges = ['cart-count-badge', 'cart-count-badge-mobile'];
    badges.forEach(badgeId => {
        const badge = document.getElementById(badgeId);
        if (badge) {
            badge.textContent = count > 0 ? count : '';
            if (count > 0) {
                badge.style.display = 'inline-block';
            } else {
                badge.style.display = 'none';
            }
        }
    });
}

// Initial fetch of cart count on page load
function fetchInitialCartCount() {
    if (document.getElementById('cart-count-badge')) { // Only if user is logged in
        fetch('/cart_count')
            .then(response => response.json())
            .then(data => updateCartCount(data.count))
            .catch(err => console.error("Could not fetch cart count", err));
    }
}

// -- OTHER UTILITY FUNCTIONS --

function addToWishlist() {
    showAlert('Wishlist functionality coming soon!', 'info');
}

// Sliding Cart Functions
function toggleCartSlider() {
    const cartSlider = document.getElementById('cartSlider');
    const overlay = document.getElementById('cartSliderOverlay');
    
    if (cartSlider.classList.contains('active')) {
        closeCartSlider();
    } else {
        openCartSlider();
    }
}

function openCartSlider() {
    const cartSlider = document.getElementById('cartSlider');
    const overlay = document.getElementById('cartSliderOverlay');
    
    // Load cart content
    loadCartSliderContent();
    
    // Show slider
    cartSlider.classList.add('active');
    overlay.classList.add('active');
    document.body.classList.add('cart-slider-open');
}

function closeCartSlider() {
    const cartSlider = document.getElementById('cartSlider');
    const overlay = document.getElementById('cartSliderOverlay');
    
    cartSlider.classList.remove('active');
    overlay.classList.remove('active');
    document.body.classList.remove('cart-slider-open');
}

function loadCartSliderContent() {
    const content = document.getElementById('cart-slider-content');
    
    fetch('/api/cart')
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                renderCartSliderContent(data.cart_items, data.total);
            } else {
                content.innerHTML = `
                    <div class="cart-slider-empty">
                        <i class="fas fa-shopping-cart"></i>
                        <p>Your cart is empty</p>
                        <a href="/products" class="btn btn-primary btn-sm">Shop Now</a>
                    </div>
                `;
            }
        })
        .catch(error => {
            console.error('Error loading cart:', error);
            content.innerHTML = `
                <div class="cart-slider-empty">
                    <i class="fas fa-exclamation-triangle"></i>
                    <p>Error loading cart</p>
                    <button onclick="loadCartSliderContent()" class="btn btn-primary btn-sm">Try Again</button>
                </div>
            `;
        });
}

function renderCartSliderContent(cartItems, total) {
    const content = document.getElementById('cart-slider-content');
    const totalElement = document.getElementById('cart-slider-total');
    
    if (!cartItems || cartItems.length === 0) {
        content.innerHTML = `
            <div class="cart-slider-empty">
                <i class="fas fa-shopping-cart"></i>
                <p>Your cart is empty</p>
                <a href="/products" class="btn btn-primary btn-sm">Shop Now</a>
            </div>
        `;
        totalElement.textContent = '$0.00';
        return;
    }
    
    let html = '';
    cartItems.forEach(item => {
        html += `
            <div class="cart-slider-item" data-item-id="${item.cart_item_id}">
                <img src="${item.product.image_url || 'https://via.placeholder.com/50x50?text=Product'}" 
                     alt="${item.product.name}">
                <div class="cart-slider-item-info">
                    <div class="cart-slider-item-name">${item.product.name}</div>
                    <div class="cart-slider-item-price">$${item.product.price.toFixed(2)} each</div>
                    <div class="cart-slider-item-quantity">
                        <button class="btn btn-outline-secondary btn-sm" 
                                onclick="updateSliderCartQuantity('${item.cart_item_id}', ${item.quantity - 1})">-</button>
                        <input type="number" value="${item.quantity}" min="1" max="${item.product.stock_quantity}"
                               onchange="updateSliderCartQuantity('${item.cart_item_id}', this.value)"
                               class="form-control form-control-sm">
                        <button class="btn btn-outline-secondary btn-sm"
                                onclick="updateSliderCartQuantity('${item.cart_item_id}', ${item.quantity + 1})">+</button>
                        <button class="btn btn-outline-danger btn-sm ms-2"
                                onclick="removeSliderCartItem('${item.cart_item_id}')">
                            <i class="fas fa-trash"></i>
                        </button>
                    </div>
                </div>
            </div>
        `;
    });
    
    content.innerHTML = html;
    totalElement.textContent = `$${total.toFixed(2)}`;
}

function updateSliderCartQuantity(cartItemId, newQuantity) {
    if (newQuantity < 1) {
        removeSliderCartItem(cartItemId);
        return;
    }
    
    fetch('/update_cart', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `cart_item_id=${cartItemId}&quantity=${newQuantity}`
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            loadCartSliderContent();
            updateCartCount(data.cart_count);
        } else {
            showAlert(data.message || 'Error updating cart', 'danger');
        }
    })
    .catch(error => {
        console.error('Error updating cart:', error);
        showAlert('Error updating cart. Please try again.', 'danger');
    });
}

function removeSliderCartItem(cartItemId) {
    fetch('/remove_from_cart', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `cart_item_id=${cartItemId}`
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            loadCartSliderContent();
            updateCartCount(data.cart_count);
            showAlert('Item removed from cart', 'success');
        } else {
            showAlert(data.message || 'Error removing item', 'danger');
        }
    })
    .catch(error => {
        console.error('Error removing item:', error);
        showAlert('Error removing item. Please try again.', 'danger');
    });
}

// Close cart slider when pressing Escape key
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        closeCartSlider();
    }
});

// Initialize common functionality when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    fetchInitialCartCount();

    // Attach handler to all add-to-cart buttons
    document.addEventListener('click', function(e) {
        if (e.target.matches('.add-to-cart') || e.target.closest('.add-to-cart')) {
            const button = e.target.closest('.add-to-cart');
            const productId = button.dataset.productId;
            
            // Find quantity input relative to the button
            const form = button.closest('form');
            const quantityInput = form ? form.querySelector('input[name="quantity"]') : null;
            
            const quantity = quantityInput ? parseInt(quantityInput.value) : (button.dataset.quantity || 1);
            
            addToCart(productId, quantity);
        }
    });

    // Lazy loading for images
    if ('IntersectionObserver' in window) {
        const lazyImages = document.querySelectorAll('img[data-src]');
        const imageObserver = new IntersectionObserver((entries, observer) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const img = entry.target;
                    img.src = img.dataset.src;
                    img.removeAttribute('data-src');
                    imageObserver.unobserve(img);
                }
            });
        });
        lazyImages.forEach(img => imageObserver.observe(img));
    }
});