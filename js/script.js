const button = document.querySelector('#btnSaludo');
const message = document.querySelector('#mensaje');

if (button && message) {
  button.addEventListener('click', () => {
    message.textContent = 'Interacción activa: la base moderna del proyecto está lista.';
  });
}
