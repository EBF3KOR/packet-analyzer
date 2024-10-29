document.getElementById('upload-form').addEventListener('submit', async (event) => {
    event.preventDefault(); // Prevent default form submission
 
    const fileInput = document.getElementById('file-input');
    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
 
    const response = await fetch('/upload', {
        method: 'POST',
        body: formData
    });
 
    const result = await response.json();
    document.getElementById('result').textContent = JSON.stringify(result, null, 2);
});